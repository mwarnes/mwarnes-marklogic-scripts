"""Tests for ml-security-gather.py against a mock Management API and IdP (no MarkLogic server needed).

Run:  python3 -m unittest discover -s scripts/Security/tests -v     (needs python3, curl and openssl)
"""
import base64
import json
import os
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "ml-security-gather.py"
PORT = 18095
ISS = "http://127.0.0.1:%d/iss/" % PORT
b64 = lambda b: base64.urlsafe_b64encode(b).rstrip(b"=").decode()

STATE = {"version": "12.1.0", "flow": "Resource server"}
ERRLOG = """2026-10-25 10:00:01.200 Info: [Event:id=OAuth Status] JWT validation failed, re-initiating authorization flow: XDMP-OAUTH: signature invalid
2026-10-25 10:00:02.100 Info: [Event:id=OAuth Status] OAuth JWT Issuer URI must be configured
2026-10-25 10:00:04.000 Info: [Event:id=External Authenticate] ldapAuthenticate() fail because authentication failure
2026-10-25 10:00:05.000 Info: [Event:id=External Authenticate] ldapAuthenticate() fail because no LDAP user
"""
ACCESS = '203.0.113.9 - - [25/Oct/2026:10:00:01 +0000] "GET /v1/x?q=secret HTTP/1.1" 401 209 - "node"\n'
N = None


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def reply(self, obj, text=False):
        self.send_response(200)
        self.send_header("Content-Type", "text/plain" if text else "application/json")
        self.end_headers()
        self.wfile.write((obj if text else json.dumps(obj)).encode())

    def do_GET(self):
        p = self.path.split("?")[0]
        if p == "/manage/v2":
            return self.reply({"local-cluster-default": {"version": STATE["version"], "name": "mock"}})
        if p == "/manage/v2/hosts":
            return self.reply({"x": {"status-list-items": {"status-list-item": [{"nameref": "h1"}]}}})
        if p == "/manage/v2/external-security":
            return self.reply({"x": {"list-items": {"list-item": [{"nameref": "oa"}, {"nameref": "ld"}]},
                                     "relations": {"relation": [{"nameref": "Security"}]}}})
        if p == "/manage/v2/external-security/oa/properties":
            return self.reply({"external-security-name": "oa", "authentication": "oauth", "authorization": "oauth", "oauth-server": {
                "oauth-flow-type": STATE["flow"], "oauth-vendor": "Other", "oauth-client-id": "client", "oauth-jwt-issuer-uri": ISS,
                "oauth-jwks-uri": "http://127.0.0.1:%d/jwks" % PORT, "oauth-jwt-alg": "RS256",
                "oauth-username-attribute": "preferred_username", "oauth-role-attribute": "groups", "oauth-client-secret": "SECRETVALUE"}})
        if p == "/manage/v2/external-security/ld/properties":
            return self.reply({"external-security-name": "ld", "authentication": "ldap", "authorization": "internal", "ldap-server": {
                "ldap-server-uri": "ldap://127.0.0.1:9", "ldap-base": "dc=x", "ldap-attribute": "uid", "ldap-password": "SECRETVALUE"}})
        if p == "/manage/v2/servers":
            return self.reply({"x": {"list-items": {"list-item": [{"nameref": "api", "groupnameref": "Default"}]}}})
        if p == "/manage/v2/servers/api/properties":
            return self.reply({"port": 9100, "authentication": "oauth", "external-security": ["oa", "ld"]})
        if p == "/manage/v2/roles":
            return self.reply({"x": {"list-items": {"list-item": [{"nameref": "reader"}]}}})
        if p == "/manage/v2/roles/reader/properties":
            return self.reply({"role-name": "reader", "external-name": ["ml-readers"]})
        if p == "/manage/v2/groups/Default/properties":
            return self.reply({"group-name": "Default", "events-activated": True, "event": ["OAuth", "External Authenticate"]})
        if p == "/manage/v2/logs":
            return self.reply(ERRLOG if "ErrorLog" in self.path else ACCESS, text=True)
        if p == "/iss/.well-known/openid-configuration":
            return self.reply({"issuer": ISS, "jwks_uri": "http://127.0.0.1:%d/jwks" % PORT})
        if p == "/jwks":
            return self.reply({"keys": [{"kty": "RSA", "kid": "k1", "alg": "RS256", "use": "sig", "n": N, "e": "AQAB"}]})
        self.send_response(404)
        self.end_headers()


class GatherTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        global N
        cls.tmp = tempfile.mkdtemp(prefix="msg-test.")
        subprocess.run(["openssl", "genrsa", "-out", cls.tmp + "/k.pem", "2048"], capture_output=True, check=True)
        mod = subprocess.run(["openssl", "rsa", "-in", cls.tmp + "/k.pem", "-noout", "-modulus"], capture_output=True, text=True).stdout.strip().split("=")[1]
        N = b64(bytes.fromhex(mod))
        cls.srv = HTTPServer(("127.0.0.1", PORT), Handler)
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls.srv.server_close()

    def setUp(self):
        STATE.update(version="12.1.0", flow="Resource server")

    def jwt(self, claims, kid="k1", tamper=False):
        h = b64(json.dumps({"alg": "RS256", "kid": kid, "typ": "JWT"}).encode())
        p = b64(json.dumps(claims).encode())
        Path(self.tmp, "si").write_bytes((h + "." + p).encode())
        sig = subprocess.run(["openssl", "dgst", "-sha256", "-sign", self.tmp + "/k.pem", self.tmp + "/si"], capture_output=True).stdout
        if tamper:
            p = b64(json.dumps(dict(claims, preferred_username="x")).encode())
        return h + "." + p + "." + b64(sig)

    def run_gather(self, *args, password="x"):
        env = dict(os.environ, MARKLOGIC_PASS=password)
        if password is None:
            env.pop("MARKLOGIC_PASS")
        out = tempfile.mkdtemp(prefix="msg-out.", dir=self.tmp)
        r = subprocess.run([sys.executable, "-I", str(SCRIPT)] + list(args) + ["--host", "127.0.0.1", "--port", str(PORT), "--scheme", "http",
                           "--user", "admin", "--out", out], env=env, capture_output=True, text=True, stdin=subprocess.DEVNULL)
        summary = Path(out, "SUMMARY.md")
        return r, (summary.read_text() if summary.exists() else ""), out

    def token_rows(self, **claims_over):
        good = {"iss": ISS, "aud": "client", "exp": int(time.time()) + 600, "preferred_username": "alice", "groups": ["ml-readers"]}
        return good

    def token_summary(self, name, token):
        f = Path(self.tmp, name)
        f.write_text(token)
        r, s, out = self.run_gather("oauth", "--external-security", "oa", "--token", str(f))
        self.assertEqual(r.returncode, 0, r.stderr)
        return s

    # ---- command line
    def test_help_lists_the_areas(self):
        r = subprocess.run([sys.executable, "-I", str(SCRIPT), "-h"], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0)
        for area in ("saml", "oauth", "ldap", "https"):
            self.assertIn(area, r.stdout)

    def test_a_wrong_option_prints_the_area_help_then_the_error(self):
        r = subprocess.run([sys.executable, "-I", str(SCRIPT), "oauth", "--host", "h", "--user", "u", "--tokn", "x"], capture_output=True, text=True)
        self.assertEqual(r.returncode, 2)
        self.assertIn("--token FILE", r.stderr)
        self.assertIn("ERROR: unrecognized arguments", r.stderr)

    def test_missing_area_prints_help(self):
        r = subprocess.run([sys.executable, "-I", str(SCRIPT)], capture_output=True, text=True)
        self.assertEqual(r.returncode, 2)
        self.assertIn("AREA", r.stderr)

    def test_missing_password_explains_how(self):
        r, s, out = self.run_gather("saml", password=None)
        self.assertEqual(r.returncode, 2)
        self.assertIn("MARKLOGIC_PASS", r.stderr)

    def test_unknown_profile_lists_the_existing_ones(self):
        r, s, out = self.run_gather("oauth", "--external-security", "nope")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("ld, oa", r.stderr)

    def test_unreachable_server_stops_with_a_hint(self):
        r = subprocess.run([sys.executable, "-I", str(SCRIPT), "saml", "--host", "127.0.0.1", "--port", "9", "--scheme", "http", "--user", "a"],
                           env=dict(os.environ, MARKLOGIC_PASS="x"), capture_output=True, text=True)
        self.assertEqual(r.returncode, 1)
        self.assertIn("Cannot connect", r.stderr)

    # ---- OAuth
    def test_good_token_passes_every_check(self):
        s = self.token_summary("t1", self.jwt(self.token_rows()))
        self.assertNotIn("| **FAIL** |", s)
        self.assertIn("token signature verifies", s)

    def test_tampered_token_fails_the_signature_check(self):
        s = self.token_summary("t2", self.jwt(self.token_rows(), tamper=True))
        self.assertIn("| **FAIL** | token signature verifies", s)

    def test_wrong_issuer_and_unknown_kid_and_unmapped_role(self):
        c = self.token_rows()
        self.assertIn("| **FAIL** | token iss = oauth-jwt-issuer-uri", self.token_summary("t3", self.jwt(dict(c, iss="http://x/"))))
        self.assertIn("| **FAIL** | token kid is in the JWKS", self.token_summary("t4", self.jwt(c, kid="rotated")))
        self.assertIn("| **FAIL** | role claim values map to a MarkLogic role", self.token_summary("t5", self.jwt(dict(c, groups=["nobody"]))))

    def test_authorization_code_flow_is_refused_on_marklogic_11(self):
        STATE.update(version="11.3.7", flow="Authorization code")
        r, s, out = self.run_gather("oauth", "--external-security", "oa")
        self.assertIn("Authorization code flow needs MarkLogic 12", s)
        STATE.update(version="12.1.0")
        r, s, out = self.run_gather("oauth", "--external-security", "oa")
        self.assertNotIn("needs MarkLogic 12", s)

    def test_secrets_are_not_written(self):
        r, s, out = self.run_gather("oauth", "--external-security", "oa")
        r2, s2, out2 = self.run_gather("ldap", "--external-security", "ld", "--no-probe")
        for o in (out, out2):
            for f in Path(o).iterdir():
                self.assertNotIn("SECRETVALUE", f.read_text(), f.name)

    def test_minimal_run_lists_what_was_not_collected(self):
        r, s, out = self.run_gather("oauth", "--external-security", "oa", "--no-probe")
        self.assertIn("## Not collected", s)
        self.assertIn("no --token given", s)
        self.assertIn("no --user-name given", s)

    def test_oauth_and_ldap_log_messages_get_hints(self):
        win = ["--logs", "--start", "2026-10-25T09:00:00Z", "--end", "2026-10-25T11:00:00Z", "--no-probe"]
        r, s, out = self.run_gather("oauth", "--external-security", "oa", *win)
        self.assertIn("`oauth-jwt-issuer-uri` is not set", s)
        self.assertIn("restarted the authorization flow", s)
        self.assertIn("401 responses in the window", s)
        r, s, out = self.run_gather("ldap", "--external-security", "ld", *win)
        self.assertIn("wrong password or default user DN", s)
        self.assertIn("check `ldap-base`", s)
        for f in Path(out).glob("AccessLog-*"):
            self.assertNotIn("q=secret", f.read_text())

    def test_start_and_end_accept_zone_offsets_and_bare_times_as_utc(self):
        # the mock ErrorLog has lines at 10:00 UTC on 2026-10-25; 11:00+02:00 is 09:00 UTC, a bare 11:00:00 is taken as UTC
        r, s, out = self.run_gather("oauth", "--external-security", "oa", "--no-probe", "--logs",
                                    "--start", "2026-10-25T11:00:00+02:00", "--end", "2026-10-25 11:00:00")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("## Logs (2026-10-25T09:00:00Z to 2026-10-25T11:00:00Z UTC)", s)
        self.assertIn("`oauth-jwt-issuer-uri` is not set", s)

    def test_a_start_that_is_not_a_time_is_rejected_with_the_accepted_formats(self):
        for bad in ("yesterday", "14:30", "26/10/2026 14:30"):
            r, s, out = self.run_gather("oauth", "--external-security", "oa", "--logs", "--start", bad)
            self.assertEqual(r.returncode, 2, bad)
            self.assertIn("2026-01-15T09:00:00Z", r.stderr)
            self.assertNotIn("Traceback", r.stderr)

    def test_list_names_ignore_related_objects(self):
        r, s, out = self.run_gather("oauth", "--no-probe")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertNotIn("Calls that failed", s)  # "Security" (a relation) was not read as a profile


# ---------------------------------------------------------------- HTTPS area: template status and duplicate subjects
HPORT = 18096


def cert_json(cid, subject, issuer, serial, ski, temporary=False, template=None, version=None, authority=False, days=90, label=None):
    now = time.time()
    fmt = lambda t: time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(t))
    cert = {"serialNumber": serial, "issuer": issuer, "subject": subject, "validity": {"notBefore": fmt(now - 86400), "notAfter": fmt(now + days * 86400)},
            "v3ext": {"subjectKeyIdentifier": {"value": ski}}}
    d = {"id": cid, "authority": str(authority).lower(), "host-name": label or subject.get("commonName"), "cert": cert}
    if template:
        d.update({"template-id": template, "template-version": str(version), "temporary": str(temporary).lower()})
    return d


CERTS = {
    "certificates": {
        "h1": cert_json("h1", {"commonName": "host.example.com"}, {"commonName": "Example CA"}, "00AA11", "AA:01", template="1", version=1),
        "h2": cert_json("h2", {"commonName": "host.example.com"}, {"commonName": "Example CA"}, "00BB22", "BB:02", template="3", version=1),
    },
    "certificate-authorities": {
        "t1": cert_json("t1", {"commonName": "Temp Certificate Authority"}, {"commonName": "Temp Certificate Authority"}, "00CC33", "CC:03",
                        temporary=True, template="2", version=1, authority=True),
        "d1": cert_json("d1", {"commonName": "Dup CA"}, {"commonName": "Root X"}, "01", "D1:01", authority=True, label="Root X"),
        "d2": cert_json("d2", {"commonName": "Dup CA"}, {"commonName": "Root X"}, "02", "D2:02", authority=True, label="Root X"),
    },
}


class HttpsHandler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def reply(self, obj):
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(obj).encode())

    def do_GET(self):
        p = self.path.split("?")[0]
        parts = p.strip("/").split("/")
        if p == "/manage/v2":
            return self.reply({"local-cluster-default": {"version": "12.1.0", "name": "mock"}})
        if p == "/manage/v2/hosts":
            return self.reply({"x": {"status-list-items": {"status-list-item": [{"nameref": "h1"}]}}})
        if p == "/manage/v2/servers":
            return self.reply({"x": {"list-items": {"list-item": [{"nameref": "srv-real", "groupnameref": "Default"}, {"nameref": "srv-temp", "groupnameref": "Default"}]}}})
        if p in ("/manage/v2/servers/srv-real/properties", "/manage/v2/servers/srv-temp/properties"):
            real = "srv-real" in p
            return self.reply({"port": 9201 if real else 9202, "authentication": "digest", "ssl-certificate-template": "Real" if real else "Temp",
                               "ssl-min-allow-tls": "TLSv1.2", "ssl-ciphers": "ECDHE-RSA-AES256-GCM-SHA384"})
        if p == "/manage/v2/certificate-templates":
            return self.reply({"x": {"list-items": {"list-item": [{"nameref": "Real", "idref": "1"}, {"nameref": "Temp", "idref": "2"}, {"nameref": "EC", "idref": "3"}]}}})
        if len(parts) == 4 and parts[2] == "certificate-templates":
            tid = parts[3]
            names = {"1": ("Real", 2, False), "2": ("Temp", 1, True), "3": ("EC", 1, False), "Real": ("Real", 2, False), "Temp": ("Temp", 1, True)}
            n, ver, gen = names[tid]
            return self.reply({"certificate-template-default": {"id": {"Real": "1", "Temp": "2"}.get(tid, tid), "template-name": n, "template-version": str(ver),
                                                                  "key-type": "rsa", "generate-temp-certificate": str(gen).lower()}})
        if len(parts) >= 3 and parts[2] in CERTS:
            if len(parts) == 3:
                return self.reply({"x": {"list-items": {"list-item": [{"idref": k, "nameref": v["host-name"]} if parts[2] == "certificate-authorities" else {"idref": k}
                                                                       for k, v in CERTS[parts[2]].items()]}}})
            return self.reply({"certificate-default": CERTS[parts[2]][parts[3]]})
        self.send_response(404)
        self.end_headers()


class HttpsAreaTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv = HTTPServer(("127.0.0.1", HPORT), HttpsHandler)
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()
        out = tempfile.mkdtemp(prefix="msg-https.")
        subprocess.run([sys.executable, "-I", str(SCRIPT), "https", "--host", "127.0.0.1", "--port", str(HPORT), "--scheme", "http", "--user", "admin",
                        "--no-probe", "--out", out], env=dict(os.environ, MARKLOGIC_PASS="x"), capture_output=True, text=True, stdin=subprocess.DEVNULL)
        cls.summary = Path(out, "SUMMARY.md").read_text()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls.srv.server_close()

    def test_a_temporary_certificate_is_labelled_and_warned_about(self):
        self.assertIn("**TEMPORARY** (generated by MarkLogic, self-signed)", self.summary)
        self.assertIn("| **WARN** | Temp: certificate is TEMPORARY", self.summary)

    def test_a_ca_signed_certificate_is_labelled_permanent(self):
        self.assertIn("**PERMANENT**, signed by a certificate authority", self.summary)
        self.assertIn("| **PASS** | Real: permanent certificate | issued by Example CA", self.summary)

    def test_template_version_mismatch_is_reported(self):
        self.assertIn("issued for template version 1", self.summary)

    def test_duplicate_host_certificates_are_classified_as_harmless(self):
        self.assertIn("(host certificates)", self.summary)
        self.assertIn("Harmless, but make sure each app server uses the intended template", self.summary)

    def test_two_different_ca_keys_with_one_subject_are_a_warning(self):
        self.assertIn("| **WARN** | duplicate subject `CN=Dup CA` (certificate authorities)", self.summary)

    def test_list_names_that_are_the_issuers_name_are_explained(self):
        self.assertIn("Certificate authority list names that differ from the certificate's subject", self.summary)
        self.assertIn("| `Root X` | `Dup CA` | `Root X` |", self.summary)


# ---------------------------------------------------------------- SAML authorization rule and the --user fallback
SPORT = 18097
SSTATE = {"version": "11.3.7", "authz": "internal", "role_external": True}


class SamlHandler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def reply(self, obj):
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(obj).encode())

    def do_GET(self):
        p = self.path.split("?")[0]
        if p == "/manage/v2":
            return self.reply({"local-cluster-default": {"version": SSTATE["version"], "name": "mock"}})
        if p == "/manage/v2/hosts":
            return self.reply({"x": {"status-list-items": {"status-list-item": [{"nameref": "h1"}]}}})
        if p == "/manage/v2/external-security":
            return self.reply({"x": {"list-items": {"list-item": [{"nameref": "sp"}]}}})
        if p == "/manage/v2/external-security/sp/properties":
            return self.reply({"external-security-name": "sp", "authentication": "saml", "authorization": SSTATE["authz"], "saml-server": {
                "saml-entity-id": "https://idp.example.com/meta", "saml-destination": "https://idp.example.com/sso", "saml-issuer": "https://ml.example.com:8013"}})
        if p == "/manage/v2/servers":
            return self.reply({"x": {"list-items": {"list-item": []}}})
        if p == "/manage/v2/roles":
            return self.reply({"x": {"list-items": {"list-item": [{"nameref": "reader"}]}}})
        if p == "/manage/v2/roles/reader/properties":
            return self.reply({"role-name": "reader", **({"external-name": ["qconsole-user"]} if SSTATE["role_external"] else {})})
        self.send_response(404)
        self.end_headers()


class SamlRuleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv = HTTPServer(("127.0.0.1", SPORT), SamlHandler)
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls.srv.server_close()

    def gather(self, **state):
        SSTATE.update(version="11.3.7", authz="internal", role_external=True)
        SSTATE.update(state)
        out = tempfile.mkdtemp(prefix="msg-saml.")
        r = subprocess.run([sys.executable, "-I", str(SCRIPT), "saml", "--host", "127.0.0.1", "--port", str(SPORT), "--scheme", "http", "--user", "admin",
                            "--external-security", "sp", "--out", out], env=dict(os.environ, MARKLOGIC_PASS="x"), capture_output=True, text=True, stdin=subprocess.DEVNULL)
        self.assertEqual(r.returncode, 0, r.stderr)
        return Path(out, "SUMMARY.md").read_text()

    def test_authorization_internal_is_guidance_not_a_failure(self):
        for v in ("11.3.7", "12.1.0", "11.2.0"):
            s = self.gather(version=v)
            self.assertIn("| **WARN** | sp: authorization is `saml`", s)
            self.assertNotIn("| **FAIL** | sp: authorization is `saml`", s)
            self.assertIn("this setting alone is not what leaves a login without roles", s)

    def test_authorization_saml_with_a_role_external_name_passes(self):
        s = self.gather(authz="saml")
        self.assertNotIn("authorization is `saml`", s)
        self.assertIn("| **PASS** | roles with external names exist", s)

    def test_no_role_external_name_fails_whatever_the_authorization_is(self):
        for az in ("saml", "internal"):
            s = self.gather(authz=az, role_external=False)
            self.assertIn("| **FAIL** | a role has an external name to receive SAML roles", s)


class UserOptionTests(unittest.TestCase):
    def run_script(self, args, env_extra):
        env = {k: v for k, v in os.environ.items() if k != "MARKLOGIC_USER"}
        env.update(env_extra)
        return subprocess.run([sys.executable, "-I", str(SCRIPT)] + args, env=env, capture_output=True, text=True, stdin=subprocess.DEVNULL)

    def test_user_can_come_from_the_environment(self):
        SSTATE.update(version="12.1.0", authz="saml", role_external=True)
        srv = HTTPServer(("127.0.0.1", SPORT + 10), SamlHandler)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            out = tempfile.mkdtemp(prefix="msg-user.")
            r = self.run_script(["saml", "--host", "127.0.0.1", "--port", str(SPORT + 10), "--scheme", "http", "--external-security", "sp", "--out", out],
                                {"MARKLOGIC_PASS": "x", "MARKLOGIC_USER": "ml-admin-2"})
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertIn("as `ml-admin-2`", Path(out, "SUMMARY.md").read_text())
        finally:
            srv.shutdown()

    def test_user_is_required_when_neither_option_nor_environment_gives_it(self):
        r = self.run_script(["saml", "--host", "127.0.0.1"], {"MARKLOGIC_PASS": "x"})
        self.assertEqual(r.returncode, 2)
        self.assertIn("--user", r.stderr)
        self.assertIn("any other administrator account", r.stderr)


if __name__ == "__main__":
    unittest.main()
