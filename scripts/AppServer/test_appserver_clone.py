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


if __name__ == "__main__":
    unittest.main()
