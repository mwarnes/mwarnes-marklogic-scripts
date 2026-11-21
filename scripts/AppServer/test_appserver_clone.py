"""Unit tests for appserver-clone.py. Run from the repo root:

    python3 -m unittest discover -s scripts/AppServer -p 'test_*.py' -v
"""
import argparse
import contextlib
import copy
import datetime
import http.client
import importlib.util
import io
import json
import os
import pathlib
import ssl
import sys
import tempfile
import unittest
import unittest.mock
import urllib.error
import urllib.parse

_PATH = pathlib.Path(__file__).with_name("appserver-clone.py")
_SPEC = importlib.util.spec_from_file_location("appserver_clone", _PATH)
ac = importlib.util.module_from_spec(_SPEC)
sys.modules[_SPEC.name] = ac
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
        self.assertEqual(str(err), "GET /manage/v2/servers/x/properties -> 404 MANAGE-NOGROUPWITHSERVER: (err:FOER0000) No such group")
        self.assertEqual(err.exit_code, ac.EXIT_API)

    def test_non_json_body(self):
        err = ac.api_error("GET", "/manage/v2", 401, b"<html>Unauthorized</html>")
        self.assertEqual(str(err), "GET /manage/v2 -> 401")
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

    def test_digest_auth_failure_without_body_is_api_error(self):
        # urllib raises HTTPError with fp=None when digest auth fails; e.read() raises KeyError before 3.10
        err = urllib.error.HTTPError("http://x", 401, "digest auth failed", {}, None)
        client, _ = self.client(err)
        with self.assertRaises(ac.ApiError) as cm:
            client.get_json("/manage/v2")
        self.assertEqual(cm.exception.status, 401)
        self.assertIn("MARKLOGIC_PASS", cm.exception.hint)

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

    def test_truncated_response_becomes_transport_error(self):
        client, _ = self.client(http.client.IncompleteRead(b"partial"))
        with self.assertRaises(ac.TransportError) as cm:
            client.get_json("/manage/v2")
        self.assertEqual(cm.exception.exit_code, ac.EXIT_API)

    def test_unsupported_auth_scheme_becomes_transport_error(self):
        client, _ = self.client(ValueError("AbstractDigestAuthHandler does not support the following scheme: 'Negotiate'"))
        with self.assertRaises(ac.TransportError) as cm:
            client.get_json("/manage/v2")
        self.assertEqual(cm.exception.exit_code, ac.EXIT_API)


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

    def test_list_servers_unexpected_shape(self):
        class Odd:
            def get_json(self, path, params=None):
                return {"server-default-list": {"list-items": {"list-item": [{"groupnameref": "G"}]}}}
        with self.assertRaises(ac.ApiError) as cm:
            ac.list_servers(Odd())
        self.assertIn("unexpected response format", str(cm.exception))

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
        self.assertIn("Groups > Default > App Servers > AppServices-Digest > Delete", cm.exception.hint)


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
        self.assertEqual(cm.exception.exit_code, ac.EXIT_PREFLIGHT)
        self.assertIn("Admin", str(cm.exception))
        self.assertEqual(fake.mutating_calls(), [])

    def test_restart_is_waited_for(self):
        fake = default_fake()
        fake.post_status, fake.restart_body = 202, RESTART_BODY
        self.run_clone(fake)
        self.assertEqual(self.waits, [RESTART_BODY])

    def test_readback_failure_still_writes_record(self):
        fake = default_fake()
        original_get = fake.get_json
        def flaky_get(path, params=None):
            if path == "/manage/v2/servers/AppServices-Digest/properties":
                raise ac.TransportError("timed out")
            return original_get(path, params)
        fake.get_json = flaky_get
        with self.assertRaises(ac.CloneError) as cm:
            self.run_clone(fake)
        self.assertEqual(cm.exception.exit_code, ac.EXIT_API)
        self.assertIn("WAS CREATED", str(cm.exception))
        self.assertTrue(os.path.exists(self.output))
        self.assertEqual(ac.load_record(self.output)["clone"], {"name": "AppServices-Digest", "port": 9000})

    def test_interrupt_during_wait_still_writes_record(self):
        fake = default_fake()
        fake.post_status, fake.restart_body = 202, RESTART_BODY
        def interrupted(client, body):
            raise KeyboardInterrupt
        with self.assertRaises(ac.CloneError) as cm:
            ac.cmd_clone(fake, self.config, clone_args(output=self.output), out=io.StringIO(), now=NOW,
                         wait=interrupted)
        self.assertEqual(cm.exception.exit_code, ac.EXIT_API)
        self.assertIn("WAS CREATED", str(cm.exception))
        self.assertIn("interrupted", str(cm.exception))
        self.assertEqual(ac.load_record(self.output)["clone"], {"name": "AppServices-Digest", "port": 9000})

    def test_post_transport_error_hints_admin_ui(self):
        fake = default_fake()
        fake.fail_post = ac.TransportError("timed out")
        with self.assertRaises(ac.TransportError) as cm:
            self.run_clone(fake)
        self.assertIn("may or may not have been created", cm.exception.hint)
        self.assertFalse(os.path.exists(self.output))

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

    def test_rename_failure_after_delete_is_a_warning(self):
        with unittest.mock.patch.object(ac.os, "replace", side_effect=OSError(13, "Permission denied")):
            code, out = self.run_remove(yes=True)
        self.assertEqual(code, ac.EXIT_OK)
        self.assertIn("deleted app server 'AppServices-Digest' from group 'Default'", out)
        self.assertIn("warning: could not rename the record", out)
        self.assertIn(self.path, out)
        self.assertTrue(os.path.exists(self.path))

    def test_delete_transport_error_hints_rerun(self):
        def broken(path, params):
            raise ac.TransportError("timed out")
        self.fake.delete = broken
        with self.assertRaises(ac.TransportError) as cm:
            self.run_remove(yes=True)
        self.assertIn("re-running --remove is safe", cm.exception.hint)
        self.assertTrue(os.path.exists(self.path))

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
        self.assertIn("error: POST /manage/v2/servers -> 400 ADMIN-PORTINUSE", err)
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

    def test_eof_at_prompt_declines(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "AppServices-Digest.json")
            ac.write_record(path, ac.build_record("ml1.example.com", "Default", "App-Services", CLONE_PROPS, now=NOW))
            fake = FakeClient([("AppServices-Digest", "Default")], {("AppServices-Digest", "Default"): CLONE_PROPS})
            out, err = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err), \
                    unittest.mock.patch("builtins.input", side_effect=EOFError), \
                    unittest.mock.patch.object(ac.sys, "stdin", FakeStdin(True)):
                code = ac.main(["--remove", path], environ=ENV, client_factory=lambda config: fake)
            self.assertEqual(code, ac.EXIT_DECLINED)
            self.assertIn("nothing was deleted", err.getvalue())
            self.assertEqual(fake.mutating_calls(), [])
            self.assertTrue(os.path.exists(path))


if __name__ == "__main__":
    unittest.main()
