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
2026-10-25 10:00:06.000 Error: LDAPClient: XDMP-LDAP-INVALID-CRED: ldap_simple_bind_s failed on ldap server ldap://ldap.example.com:389: Invalid credentials (49)
2026-10-25 10:00:07.000 Info: [Event:id=External Authenticate] ExternalSecurity[ld] ldapAuthenticate() fail
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
            return self.reply({"x": {"list-items": {"list-item": [{"nameref": "oa"}, {"nameref": "ld"}] + ([{"nameref": "ob"}] if STATE.get("extra_oauth") else [])},
                                     "relations": {"relation": [{"nameref": "Security"}]}}})
        if p in ("/manage/v2/external-security/oa/properties", "/manage/v2/external-security/ob/properties"):
            return self.reply({"external-security-name": "oa", "authentication": "oauth", "authorization": STATE.get("authz", "oauth"), "oauth-server": {
                **({"oauth-redirect-uri": STATE["redirect_uri"]} if STATE.get("redirect_uri") else {}),
                "oauth-flow-type": STATE["flow"], "oauth-vendor": "Other", "oauth-client-id": "client", "oauth-jwt-issuer-uri": ISS,
                "oauth-jwks-uri": "http://127.0.0.1:%d/jwks" % PORT, "oauth-jwt-alg": "RS256",
                "oauth-username-attribute": "preferred_username", "oauth-role-attribute": "groups", "oauth-client-secret": "SECRETVALUE"}})
        if p == "/manage/v2/external-security/ld/properties":
            return self.reply({"external-security-name": "ld", "authentication": "ldap", "authorization": STATE.get("ldap_authz", "internal"), "ldap-server": {
                "ldap-server-uri": STATE.get("ldap_uri", "ldap://127.0.0.1:9"), "ldap-base": "dc=x,dc=com", "ldap-attribute": "uid", "ldap-default-user": "uid=search,dc=x,dc=com", "ldap-password": "SECRETVALUE"}})
        if p == "/manage/v2/servers":
            return self.reply({"x": {"list-items": {"list-item": [{"nameref": "api", "groupnameref": "Default"}]}}})
        if p == "/manage/v2/servers/api/properties":
            return self.reply({"port": 9100, "authentication": STATE.get("api_auth", "oauth"), "external-security": STATE.get("api_ext", ["oa", "ld"]),
                               **({"ssl-certificate-template": "T"} if STATE.get("api_tpl") else {})})
        if p == "/manage/v2/roles":
            return self.reply({"x": {"list-items": {"list-item": [{"nameref": "reader"}]}}})
        if p == "/manage/v2/roles/reader/properties":
            return self.reply({"role-name": "reader", "external-name": ["ml-readers"] + STATE.get("role_dns", [])})
        if p == "/manage/v2/groups/Default/properties":
            return self.reply({"group-name": "Default", "events-activated": True, "event": ["OAuth", "External Authenticate"]})
        if p == "/manage/v2/logs":
            return self.reply((ERRLOG + STATE.get("errlog_extra", "")) if "ErrorLog" in self.path else ACCESS + STATE.get("access_extra", ""), text=True)
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
        for k in ("authz", "redirect_uri", "api_auth", "api_tpl", "api_ext", "ldap_uri", "ldap_authz"):
            STATE.pop(k, None)

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

    def test_authorization_code_and_secrets_of_a_token_request_are_removed(self):
        win = ["--logs", "--start", "2026-10-25T09:00:00Z", "--end", "2026-10-25T11:00:00Z", "--no-probe"]
        STATE["errlog_extra"] = ("2026-10-25 10:00:08.000 Info: [Event:id=OAuth Communications] HTTP POST to: https://idp.example.com/token/ Client ID: c "
                                 "Data: grant_type=authorization_code&redirect_uri=https%3a//ml.example.com&code_verifier=VERIFIER123&code=ONETIMECODE456&client_secret=CSECRET789\n")
        try:
            r, s, out = self.run_gather("oauth", "--external-security", "oa", *win)
        finally:
            STATE.pop("errlog_extra", None)
        text = "".join(f.read_text() for f in Path(out).glob("ErrorLog-*")) + s
        for secret in ("VERIFIER123", "ONETIMECODE456", "CSECRET789"):
            self.assertNotIn(secret, text)
        self.assertIn("grant_type=authorization_code", text)

    def test_a_token_with_several_oauth_profiles_is_listed_as_not_collected(self):
        f = Path(self.tmp, "tok-multi")
        f.write_text(self.jwt({"iss": ISS, "aud": "client", "exp": int(time.time()) + 600, "preferred_username": "alice", "groups": ["ml-readers"]}))
        STATE["extra_oauth"] = True
        try:
            r, s, out = self.run_gather("oauth", "--token", str(f), "--no-probe")
        finally:
            STATE.pop("extra_oauth", None)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("pass --external-security NAME", s)
        self.assertRegex(s, r"\| Token comparison \| several OAuth profiles exist")

    def test_identical_check_rows_are_shown_once(self):
        STATE["extra_oauth"] = True
        try:
            r, s, out = self.run_gather("oauth", "--no-probe")
        finally:
            STATE.pop("extra_oauth", None)
        rows = [l for l in s.splitlines() if l.startswith("| **")]
        self.assertEqual(len(rows), len(set(rows)))

    def ldap_groups_summary(self, role_dns, *extra):
        STATE.update(ldap_authz="ldap", role_dns=role_dns)
        try:
            r, s, out = self.run_gather("ldap", "--external-security", "ld", "--no-probe", *extra)
        finally:
            for k in ("ldap_authz", "role_dns", "errlog_extra", "access_extra"):
                STATE.pop(k, None)
        self.assertEqual(r.returncode, 0, r.stderr)
        return s

    def test_group_dn_outside_ldap_base_is_warned_about(self):
        s = self.ldap_groups_summary(["cn=lab-users,dc=x,dc=org"])
        self.assertRegex(s, r"\*\*WARN\*\* \| ld: no role external name is a group DN under ldap-base `dc=x,dc=com`")
        self.assertIn("cn=lab-users,dc=x,dc=org", s)
        self.assertNotIn("no memberOf/member lookup attribute", s)

    def test_group_dn_under_ldap_base_passes_whatever_the_case_and_spacing(self):
        s = self.ldap_groups_summary(["CN=lab-users, DC=X, dc=com"])
        self.assertRegex(s, r"\*\*PASS\*\* \| ld: a role external name is a group DN under ldap-base")
        self.assertNotIn("no role external name is a group DN", s)

    def test_a_near_miss_suffix_is_warned_about_even_when_another_role_matches(self):
        s = self.ldap_groups_summary(["cn=ok,dc=x,dc=com", "cn=typo,dc=x,dc=org"])
        self.assertRegex(s, r"\*\*WARN\*\* \| ld: a role external name is a group DN that looks like ldap-base")
        self.assertIn("cn=typo,dc=x,dc=org", s)

    def test_a_dn_of_another_directory_is_only_information(self):
        s = self.ldap_groups_summary(["cn=ok,dc=x,dc=com", "cn=other,o=elsewhere"])
        self.assertRegex(s, r"\*\*INFO\*\* \| ld: other role external names are DNs outside ldap-base")
        self.assertNotIn("looks like ldap-base", s)

    def test_no_dn_shaped_external_name_is_warned_about(self):
        s = self.ldap_groups_summary([])
        self.assertIn("No role external name looks like a DN at all", s)

    def test_authorization_internal_does_not_get_the_group_dn_check(self):
        r, s, out = self.run_gather("ldap", "--external-security", "ld", "--no-probe")
        self.assertNotIn("group DN under ldap-base", s)

    def test_a_login_that_passed_and_then_got_403_is_explained(self):
        STATE["errlog_extra"] = "2026-10-25 10:00:08.000 Info: [Event:id=External Authenticate] ExternalSecurity[ld] ldapAuthenticate() pass bob\n"
        STATE["access_extra"] = '203.0.113.9 - bob [25/Oct/2026:10:00:09 +0000] "GET /qconsole/ HTTP/1.1" 403 0 - "curl"\n'
        win = ["--logs", "--start", "2026-10-25T09:00:00Z", "--end", "2026-10-25T11:00:00Z"]
        s = self.ldap_groups_summary(["cn=lab-users,dc=x,dc=org"], *win)
        self.assertIn("LDAP login passed, then the request was refused (403)", s)

    def test_the_conclusion_names_the_first_failure_or_says_all_good(self):
        good = {"iss": ISS, "aud": "client", "exp": int(time.time()) + 600, "preferred_username": "alice", "groups": ["ml-readers"]}
        s = self.token_summary("tok-good", self.jwt(good))
        self.assertIn("## Conclusion", s)
        self.assertIn("**All good: no failure and no warning in what was collected.**", s)
        self.assertLess(s.index("## Conclusion"), s.index("## Check results"))
        s = self.token_summary("tok-bad", self.jwt(dict(good, iss="http://elsewhere/")))
        self.assertIn("**Root cause to look at first: token iss = oauth-jwt-issuer-uri**", s)
        self.assertNotIn("All good", s)
        self.assertRegex(s, r"\(\d+ failure\(s\) and \d+ warning\(s\) in total")

    def test_all_good_says_when_parts_were_not_collected(self):
        r, s, out = self.run_gather("oauth", "--external-security", "oa", "--no-probe")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("## Conclusion", s)
        if "All good" in s:
            self.assertIn("this verdict covers only what was collected", s)

    def test_conclusion_ranks_expiry_warnings_last_and_says_probable_cause_when_the_login_stalled(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location("gather", SCRIPT)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        ranked = "\n".join(mod.conclusion_lines([("WARN", "client certificate #1 expires soon", "29 days left"), ("WARN", "the real warning", "this is what to look at.")], [], []))
        self.assertIn("look at: the real warning**", ranked)
        only_expiry = "\n".join(mod.conclusion_lines([("WARN", "client certificate #1 expires soon", "29 days left")], [], []))
        self.assertIn("look at: client certificate #1 expires soon**", only_expiry)
        stalled = "\n".join(mod.conclusion_lines([("WARN", "browser was sent to the IdP but never came back", "no return."),
                                                   ("WARN", "x: oauth-authorization-server-uri = discovery authorization_endpoint", "config a / discovery b")], [], []))
        self.assertIn("**Probable cause: x: oauth-authorization-server-uri = discovery authorization_endpoint**", stalled)
        self.assertIn("the login did not complete", stalled)
        self.assertNotIn("No failure found", stalled)
        only_stalled = "\n".join(mod.conclusion_lines([("WARN", "browser was sent to the IdP but never came back", "no return.")], [], []))
        self.assertIn("**Probable cause: browser was sent to the IdP but never came back**", only_stalled)

    def test_tls_policy_of_marklogic_11_has_no_tls_13_flag(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location("gather", SCRIPT)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        base = {"ssl-disable-sslv3": True, "ssl-disable-tlsv1": True, "ssl-disable-tlsv1-1": True}
        self.assertEqual(mod.tls_policy(dict(base, **{"ssl-disable-tlsv1-2": True}), 11)[0], "allowed: see ssl-disable-* flags")
        self.assertEqual(mod.tls_policy(dict(base, **{"ssl-disable-tlsv1-2": False}), 11)[0], "allowed: TLSv1.2")
        self.assertEqual(mod.tls_policy({"ssl-min-allow-tls": "TLSv1.3"}, 12)[0], "minimum TLSv1.3")

    def test_a_refused_login_after_a_pass_says_probable_cause_and_ranks_the_symptom_last(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location("gather", SCRIPT)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        only = "\n".join(mod.conclusion_lines([("WARN", "certificate login passed, then the request was refused (403)", "no role for the URL.")], [], []))
        self.assertIn("**Probable cause: certificate login passed, then the request was refused (403)**", only)
        self.assertIn("the request was refused (HTTP 403) after the login passed", only)
        both = "\n".join(mod.conclusion_lines([("WARN", "certificate login passed, then the request was refused (403)", "no role."),
                                              ("WARN", "p: the LDAP connection is not encrypted", "clear text.")], [], []))
        self.assertIn("**Probable cause: p: the LDAP connection is not encrypted**", both)

    def test_a_log_row_failure_adds_the_warning_that_names_the_cause(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location("gather", SCRIPT)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        text = "\n".join(mod.conclusion_lines([("FAIL", "CERTIFICATE error, first at 2026-01-01 10:00:00.000 (1 time)", "`[Event:id=External Authenticate] unknown user` - Four causes write this same line."),
                                              ("WARN", "p: ldap-attribute `x` while the DN starts with uid=", "the entry may lack it. More."),
                                              ("WARN", "client certificate #1 expires soon", "29 days left")], [], []))
        self.assertIn("Also look at: **p: ldap-attribute `x` while the DN starts with uid=**", text)
        self.assertNotIn("expires soon**", text)

    def test_conclusion_text_helpers(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location("gather", SCRIPT)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        none = mod.conclusion_lines([], [], [])
        self.assertIn("**No verdict: no check could be run.**", none)
        warn = mod.conclusion_lines([("WARN", "something odd", "details of it. More text follows here.")], [("x", "y", "z")], [])
        text = "\n".join(warn)
        self.assertIn("**No failure found. 1 warning(s); look at: something odd**", text)
        self.assertIn("1 part(s) were not collected", text)
        fail = "\n".join(mod.conclusion_lines([("PASS", "a", ""), ("FAIL", "the thing", "the thing is broken in this and that way, and this sentence is long enough. Second sentence. Third sentence."), ("FAIL", "other", "x")], [], []))
        self.assertIn("**Root cause to look at first: the thing**", fail)
        self.assertIn("The thing is broken in this and that way, and this sentence is long enough. Second sentence.", fail)
        self.assertNotIn("Third sentence", fail)
        hintless = "\n".join(mod.conclusion_lines([("FAIL", "OAUTH error, first at 2026-01-01 10:00:00.000 (1 time)", "`[Event:id=OAuth Status] bare line`"),
                                                  ("FAIL", "OAUTH error, first at 2026-01-01 10:00:01.000 (1 time)", "`[Event:id=OAuth Status] other line` - The explained cause is here. More about it.")], [], []))
        self.assertIn("The explained cause is here. More about it.", hintless)
        self.assertIn("2 failure(s) and 0 warning(s)", fail)

    def test_the_ldap_area_probes_the_directory_like_the_certificate_area(self):
        r, s, out = self.run_gather("ldap", "--external-security", "ld")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertRegex(s, r"\*\*FAIL\*\* \| ld: the LDAP server answers on 127.0.0.1:9")
        STATE["ldap_uri"] = "ldap://no-such-host.invalid:389"
        r, s, out = self.run_gather("ldap", "--external-security", "ld")
        self.assertRegex(s, r"\*\*FAIL\*\* \| ld: the LDAP host name resolves")
        self.assertIn("**Root cause to look at first: ld: the LDAP host name resolves**", s)

    def test_the_ldap_area_prints_the_commands_that_tell_the_search_account_from_the_user_bind(self):
        r, s, out = self.run_gather("ldap", "--external-security", "ld", "--no-probe")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertRegex(s, r"the search account `ldapwhoami -x(?: -ZZ)? -H ldap://127.0.0.1:9 -D \"")
        self.assertIn("then the user's own bind `ldapwhoami", s)
        self.assertNotIn("SECRETVALUE", s)

    def test_a_refused_bind_hint_says_the_log_cannot_tell_search_account_from_user(self):
        win = ["--logs", "--start", "2026-10-25T09:00:00Z", "--end", "2026-10-25T11:00:00Z", "--no-probe"]
        r, s, out = self.run_gather("ldap", "--external-security", "ld", *win)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("and the ErrorLog does not say which (the lines are identical in both cases)", s)

    def test_a_directory_user_is_not_a_failure_with_authorization_ldap(self):
        STATE["ldap_authz"] = "ldap"
        r, s, out = self.run_gather("ldap", "--external-security", "ld", "--no-probe", "--user-name", "nobody")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertRegex(s, r"\*\*INFO\*\* \| user nobody is not a MarkLogic user")
        self.assertNotIn("user nobody exists", s)
        STATE["ldap_authz"] = "internal"
        r, s, out = self.run_gather("ldap", "--external-security", "ld", "--no-probe", "--user-name", "nobody")
        self.assertRegex(s, r"\*\*FAIL\*\* \| user nobody exists")

    def test_appserver_names_a_server_without_the_profile(self):
        STATE["api_ext"] = []
        r, s, out = self.run_gather("ldap", "--external-security", "ld", "--no-probe", "--appserver", "api")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertRegex(s, r"\*\*FAIL\*\* \| app server api has an external security profile")
        self.assertIn("externalAuthenticate failed because no external security is configured", s)
        STATE["api_ext"] = ["oa"]
        r, s, out = self.run_gather("ldap", "--external-security", "ld", "--no-probe", "--appserver", "api")
        self.assertRegex(s, r"\*\*FAIL\*\* \| app server api uses a LDAP profile")
        STATE.pop("api_ext")
        r, s, out = self.run_gather("ldap", "--external-security", "ld", "--no-probe", "--appserver", "api")
        self.assertRegex(s, r"\*\*PASS\*\* \| app server api uses a LDAP profile \| ld")
        r, s, out = self.run_gather("ldap", "--external-security", "ld", "--no-probe", "--appserver", "nope")
        self.assertRegex(s, r"\*\*FAIL\*\* \| app server nope exists")

    def test_an_oauth_profile_on_an_app_server_that_is_not_oauth_is_warned_about(self):
        STATE["api_auth"] = "basic"
        r, s, out = self.run_gather("oauth", "--external-security", "oa", "--no-probe")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertRegex(s, r"\*\*WARN\*\* \| app server api uses oauth authentication \| authentication is `basic`, not `oauth`")
        STATE["api_auth"] = "oauth"
        r, s, out = self.run_gather("oauth", "--external-security", "oa", "--no-probe")
        self.assertNotIn("uses oauth authentication", s)

    def test_an_http_app_server_with_an_https_redirect_uri_fails(self):
        STATE.update(flow="Authorization code", redirect_uri="https://ml.example.com:9100")
        r, s, out = self.run_gather("oauth", "--external-security", "oa", "--no-probe")
        self.assertRegex(s, r"\*\*FAIL\*\* \| app server api serves the https redirect URI of profile oa")
        STATE["api_tpl"] = True
        r, s, out = self.run_gather("oauth", "--external-security", "oa", "--no-probe")
        self.assertNotIn("serves the https redirect URI", s)

    def test_authorization_internal_is_guidance_for_oauth(self):
        STATE["authz"] = "internal"
        r, s, out = self.run_gather("oauth", "--external-security", "oa", "--no-probe")
        self.assertRegex(s, r"\*\*INFO\*\* \| oa: authorization is internal")
        self.assertNotRegex(s, r"\*\*FAIL\*\* \| oa: authorization")

    def test_a_token_for_another_client_id_fails(self):
        good = {"iss": ISS, "aud": "client", "exp": int(time.time()) + 600, "preferred_username": "alice", "groups": ["ml-readers"]}
        s = self.token_summary("tok-cid", self.jwt(dict(good, aud="someone-else")))
        self.assertRegex(s, r"\*\*FAIL\*\* \| token audience / authorized party contains the client id")
        self.assertIn("JWT client id validation fails", s)

    def test_new_oauth_log_hints(self):
        win = ["--logs", "--start", "2026-10-25T09:00:00Z", "--end", "2026-10-25T11:00:00Z", "--no-probe"]
        STATE["errlog_extra"] = ("2026-10-25 10:00:08.000 Info: [Event:id=OAuth Status] XDMP-OAUTH: JWT client id validation fails\n"
                                 "2026-10-25 10:00:09.000 Info: [Event:id=OAuth Status] XDMP-OAUTH: JWT verification failed. Please check the JWT signature, token format and token expiration\n"
                                 "2026-10-25 10:00:10.000 Info: [Event:id=OAuth Status] XDMP-INTERNAL: invalid json while reading the key set\n")
        try:
            r, s, out = self.run_gather("oauth", "--external-security", "oa", *win)
        finally:
            STATE.pop("errlog_extra", None)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("is not the client id in the token", s)
        self.assertIn("one message. If the signature check of `--token` passes, the usual cause is an expired token", s)
        self.assertIn("did not return a key set", s)

    OWIN = ["--logs", "--start", "2026-10-25T09:00:00Z", "--end", "2026-10-25T11:00:00Z", "--no-probe"]

    def oauth_logs(self, errlog, *extra, access=""):
        STATE["errlog_extra"] = errlog
        if access:
            STATE["access_extra"] = access
        try:
            r, s, out = self.run_gather("oauth", "--external-security", "oa", *(list(self.OWIN) + list(extra)))
        finally:
            STATE.pop("errlog_extra", None)
            STATE.pop("access_extra", None)
        self.assertEqual(r.returncode, 0, r.stderr)
        return s

    def test_role_claim_values_in_the_trace_are_matched_to_role_external_names(self):
        s = self.oauth_logs("2026-10-25 10:00:08.000 Info: [Event:id=OAuth Status] OAuth Authentication with Username: [bob] Roles: [ml-reader]\n")
        self.assertRegex(s, r"\*\*FAIL\*\* \| role claim values of bob map to a MarkLogic role")
        self.assertIn("Closest role external name(s) among the 1 on this cluster: `ml-readers`", s)
        s = self.oauth_logs("2026-10-25 10:00:08.000 Info: [Event:id=OAuth Status] OAuth Authentication with Username: [bob] Roles: [ML-Readers]\n")
        self.assertRegex(s, r"\*\*PASS\*\* \| role claim values of bob map to MarkLogic roles \| `ML-Readers` -> reader")

    def test_a_trace_line_without_roles_means_the_token_has_no_role_claim(self):
        s = self.oauth_logs("2026-10-25 10:00:08.000 Info: [Event:id=OAuth Status] OAuth Authentication with Username: [bob]\n")
        self.assertRegex(s, r"\*\*FAIL\*\* \| the token for bob carries no role claim values")

    def test_json_processing_echoes_are_not_error_rows_and_an_html_answer_gets_a_hint(self):
        s = self.oauth_logs("2026-10-25 10:00:08.000 Info: [Event:id=OAuth Communications] Response code: 403 Response: <!DOCTYPE html> <html> the request failed\n"
                            "2026-10-25 10:00:08.001 Info: [Event:id=OAuth JSON Processing] Extracting key: 'error' from: <!DOCTYPE html> <html>\n"
                            "2026-10-25 10:00:08.002 Info: [Event:id=OAuth JSON Processing] Unable to process text as JSON: <!DOCTYPE html>\n")
        self.assertNotIn("Extracting key", s.split("## Check results")[1])
        self.assertNotIn("Unable to process text as JSON", s.split("## Check results")[1])
        self.assertIn("the URL is not the IdP's token endpoint", s)

    def test_an_expired_token_is_named_when_the_token_and_the_failed_request_are_known(self):
        import calendar
        exp = calendar.timegm((2026, 10, 25, 9, 0, 0))
        f = Path(self.tmp, "tok-expired")
        f.write_text(self.jwt({"iss": ISS, "aud": "client", "exp": exp, "preferred_username": "alice", "groups": ["ml-readers"]}))
        s = self.oauth_logs("2026-10-25 10:00:08.000 Info: [Event:id=OAuth Status] JWT verification failed. Please check the JWT signature, token format and token expiration.\n", "--token", str(f))
        self.assertRegex(s, r"\*\*FAIL\*\* \| the token was expired when it was used")

    def test_an_html_page_instead_of_the_jwks_is_named(self):
        s = self.oauth_logs("2026-10-25 10:00:08.000 Info: [Event:id=OAuth Communications] JWKS Response:      <!DOCTYPE html> <html lang=\"en\"> <head>\n")
        self.assertRegex(s, r"\*\*FAIL\*\* \| MarkLogic fetched an HTML page instead of the JWKS")

    def test_an_oauth_login_that_passed_and_got_403_is_explained(self):
        s = self.oauth_logs("2026-10-25 10:00:08.000 Info: [Event:id=OAuth Status] OAuth authenticated!\n",
                            access='203.0.113.9 - bob [25/Oct/2026:10:00:09 +0000] "GET /v1/x HTTP/1.1" 403 0 - "curl"\n')
        self.assertRegex(s, r"\*\*WARN\*\* \| OAuth login passed, then the request was refused \(403\)")

    def test_a_missing_role_claim_in_the_token_fails_and_a_near_miss_names_the_closest_role(self):
        good = {"iss": ISS, "aud": "client", "exp": int(time.time()) + 600, "preferred_username": "alice"}
        s = self.token_summary("tok-noroles", self.jwt(dict(good)))
        self.assertRegex(s, r"\*\*FAIL\*\* \| token has role claim values in `groups`")
        s = self.token_summary("tok-near", self.jwt(dict(good, groups=["ml-reader"])))
        self.assertIn("Closest role external name(s) among the 1 on this cluster: `ml-readers`", s)

    def test_a_url_is_not_capitalised_in_the_conclusion(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location("gather", SCRIPT)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        text = "\n".join(mod.conclusion_lines([("FAIL", "JWKS readable", "https://idp.example.com/jwks: HTTP 404.")], [], []))
        self.assertIn("https://idp.example.com/jwks: HTTP 404.", text)
        self.assertNotIn("Https://", text)

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
        self.assertIn("The directory refused a bind", s)
        self.assertIn("the search found no entry", s)
        self.assertIn("needs a user whose external name is the user's full DN", s)
        for f in Path(out).glob("AccessLog-*"):
            self.assertNotIn("q=secret", f.read_text())

    AC_FIRST_LEG = (
        "2026-10-25 10:00:06.000 Info: [Event:id=OAuth Status] getRedirectURI() called with stateVal: (empty)\n"
        "2026-10-25 10:00:06.001 Info: [Event:id=OAuth Status] OAuth redirect URI: https://idp.example/application/o/authorize/?state=x\n"
        "2026-10-25 10:00:06.002 Info: [Event:id=External Authenticate] External authentication failed: user=\n")

    def test_authorization_code_first_leg_is_not_an_error_but_a_missing_return_is_warned(self):
        win = ["--logs", "--start", "2026-10-25T09:00:00Z", "--end", "2026-10-25T11:00:00Z", "--no-probe"]
        STATE["errlog_extra"] = self.AC_FIRST_LEG
        try:
            r, s, out = self.run_gather("oauth", "--external-security", "oa", *win)
        finally:
            STATE.pop("errlog_extra", None)
        self.assertNotIn("stateVal: (empty)` -", s)
        self.assertNotIn("External authentication failed: user=` -", s)
        self.assertIn("browser was sent to the IdP but never came back", s)

    def test_idp_oauth_error_gets_a_hint_and_no_missing_return_warning(self):
        win = ["--logs", "--start", "2026-10-25T09:00:00Z", "--end", "2026-10-25T11:00:00Z", "--no-probe"]
        STATE["errlog_extra"] = self.AC_FIRST_LEG + "2026-10-25 10:00:07.000 Info: [Event:id=OAuth Status] OAuth Error: 'invalid_request',  Description: The request is otherwise malformed\n"
        try:
            r, s, out = self.run_gather("oauth", "--external-security", "oa", *win)
        finally:
            STATE.pop("errlog_extra", None)
        self.assertIn("does not allow the `authorization_code` grant type", s)
        self.assertNotIn("never came back", s)

    def test_tokens_in_log_lines_are_removed_whole(self):
        win = ["--logs", "--start", "2026-10-25T09:00:00Z", "--end", "2026-10-25T11:00:00Z", "--no-probe"]
        STATE["errlog_extra"] = ("2026-10-25 10:00:08.000 Info: [Event:id=OAuth Status] OAuth JWT Access Token: eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJodHRwIn0.SIGNATUREPARTxyz123\n"
                                 '2026-10-25 10:00:09.000 Info: [Event:id=OAuth Communications] Response code: 200 Response: {"access_token": "eyJa.eyJb.SECONDSIG987", "x": 1}\n'
                                 "2026-10-25 10:00:10.000 Info: [Event:id=OAuth Status] OAuth JWT Access Token: <163 chars removed>.<779 chars removed>.THIRDSIGabc456\n")
        try:
            r, s, out = self.run_gather("oauth", "--external-security", "oa", *win)
        finally:
            STATE.pop("errlog_extra", None)
        text = "".join(f.read_text() for f in Path(out).glob("ErrorLog-*")) + s
        for sig in ("SIGNATUREPARTxyz123", "SECONDSIG987", "THIRDSIGabc456"):
            self.assertNotIn(sig, text)

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
                "saml-entity-id": "https://idp.example.com/meta", "saml-destination": "https://idp.example.com/sso", "saml-issuer": SSTATE.get("issuer", "https://ml.example.com:8013"),
                **({"saml-sp-certificate": SSTATE["sp_cert"], "saml-sp-private-key": "ENCRYPTEDKEYGARBAGE0123456789"} if SSTATE.get("sp_cert") else {})}})
        if p == "/manage/v2/servers":
            return self.reply({"x": {"list-items": {"list-item": [{"nameref": "api", "groupnameref": "Default"}] if SSTATE.get("server") else []}}})
        if p == "/manage/v2/servers/api/properties" and SSTATE.get("server"):
            return self.reply(dict({"port": 8013, "authentication": "saml", "ssl-certificate-template": "T", "external-security": ["sp"]}, **SSTATE["server"]))
        if p == "/manage/v2/roles":
            return self.reply({"x": {"list-items": {"list-item": [{"nameref": "reader"}]}}})
        if p == "/manage/v2/roles/reader/properties":
            return self.reply({"role-name": "reader", **({"external-name": SSTATE.get("role_names", ["qconsole-user"])} if SSTATE["role_external"] else {})})
        if p == "/manage/v2/logs":
            body = SSTATE.get("errlog", "") if "ErrorLog" in self.path else ""
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(body.encode())
            return
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

    def gather_logs(self, group, role_names):
        SSTATE.update(version="11.3.7", authz="saml", role_external=True, role_names=role_names, errlog=(
            "2026-10-25 10:00:01.000 Info: [Event:id=SAML Response] Saml Response samlId:c123 Username:alice Group: %s Valid from:2026-10-25T09:59:00Z Valid until:2026-10-25T10:05:00Z\n" % group))
        out = tempfile.mkdtemp(prefix="msg-saml.")
        try:
            r = subprocess.run([sys.executable, "-I", str(SCRIPT), "saml", "--host", "127.0.0.1", "--port", str(SPORT), "--scheme", "http", "--user", "admin",
                                "--external-security", "sp", "--logs", "--start", "2026-10-25T09:00:00Z", "--end", "2026-10-25T11:00:00Z", "--out", out],
                               env=dict(os.environ, MARKLOGIC_PASS="x"), capture_output=True, text=True, stdin=subprocess.DEVNULL)
        finally:
            for k in ("role_names", "errlog"):
                SSTATE.pop(k, None)
        self.assertEqual(r.returncode, 0, r.stderr)
        return Path(out, "SUMMARY.md").read_text()

    def gather_server(self, **state):
        SSTATE.update(version="11.3.7", authz="saml", role_external=True)
        SSTATE.update(state)
        out = tempfile.mkdtemp(prefix="msg-saml.")
        try:
            r = subprocess.run([sys.executable, "-I", str(SCRIPT), "saml", "--host", "127.0.0.1", "--port", str(SPORT), "--scheme", "http", "--user", "admin",
                                "--external-security", "sp", "--out", out], env=dict(os.environ, MARKLOGIC_PASS="x"), capture_output=True, text=True, stdin=subprocess.DEVNULL)
        finally:
            for k in ("server", "issuer", "sp_cert"):
                SSTATE.pop(k, None)
        self.assertEqual(r.returncode, 0, r.stderr)
        return Path(out, "SUMMARY.md").read_text()

    def test_an_app_server_that_is_not_saml_but_has_a_saml_profile_is_warned_about(self):
        s = self.gather_server(server={"authentication": "basic"})
        self.assertRegex(s, r"\*\*WARN\*\* \| app server api uses saml authentication \| authentication is `basic`, not `saml`")
        s = self.gather_server(server={"authentication": "saml"})
        self.assertNotIn("uses saml authentication", s)

    def test_a_redirect_in_the_trace_is_not_blamed_on_the_idp_for_a_non_saml_app_server(self):
        SSTATE["errlog"] = ("2026-10-25 10:00:01.000 Info: [Event:id=SAML] Saml Redirect to IDP: https://idp.example.com/sso?SAMLRequest=abc\n")
        try:
            SSTATE.update(version="11.3.7", authz="saml", role_external=True, server={"authentication": "basic"})
            out = tempfile.mkdtemp(prefix="msg-saml.")
            r = subprocess.run([sys.executable, "-I", str(SCRIPT), "saml", "--host", "127.0.0.1", "--port", str(SPORT), "--scheme", "http", "--user", "admin", "--external-security", "sp",
                                "--logs", "--start", "2026-10-25T09:00:00Z", "--end", "2026-10-25T11:00:00Z", "--out", out],
                               env=dict(os.environ, MARKLOGIC_PASS="x"), capture_output=True, text=True, stdin=subprocess.DEVNULL)
        finally:
            for k in ("errlog", "server"):
                SSTATE.pop(k, None)
        s = Path(out, "SUMMARY.md").read_text()
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("uses saml authentication", s)
        self.assertNotIn("browser was sent to the IdP but no SAML response came back", s)
        self.assertIn("does not use saml authentication, so its clients get a password challenge", s)

    def test_an_http_app_server_with_an_https_issuer_fails(self):
        s = self.gather_server(server={"ssl-certificate-template": None}, issuer="https://ml.example.com:8013")
        self.assertRegex(s, r"\*\*FAIL\*\* \| app server api serves the https URL of profile sp")
        s = self.gather_server(server={}, issuer="https://ml.example.com:8013")
        self.assertNotIn("serves the https URL", s)

    def test_an_issuer_port_that_is_not_the_app_server_port_is_a_lead(self):
        s = self.gather_server(server={"port": 8057}, issuer="https://ml.example.com:9999")
        self.assertRegex(s, r"\*\*WARN\*\* \| app server api: saml-issuer port matches the app server port")
        s = self.gather_server(server={"port": 8013}, issuer="https://ml.example.com:8013")
        self.assertNotIn("saml-issuer port matches", s)

    def test_the_sp_key_pair_is_not_compared_and_no_key_text_leaks(self):
        d = tempfile.mkdtemp(prefix="msg-spcert.")
        subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-keyout", d + "/k.pem", "-out", d + "/c.pem", "-subj", "/CN=sp.example.com", "-days", "30"],
                       capture_output=True, check=True)
        s = self.gather_server(sp_cert=Path(d, "c.pem").read_text())
        self.assertRegex(s, r"\*\*INFO\*\* \| sp: SP private key not compared with saml-sp-certificate")
        self.assertRegex(s, r"SP certificate public key SHA-256: `[0-9a-f]{64}`")
        self.assertNotIn("ENCRYPTEDKEYGARBAGE", s)
        self.assertNotIn("PRIVATE KEY", s)

    def test_a_response_with_no_group_values_is_named(self):
        for grp in ("", "alice"):   # the trace's Group field holds the NameID attribute's value too
            s = self.gather_logs(grp, ["qconsole-user"])
            self.assertRegex(s, r"\*\*FAIL\*\* \| the assertion for alice carries no group values")
            self.assertNotIn("Closest role external name", s)
        self.assertIn("the attribute name does not matter", s)

    def test_a_group_value_matches_a_role_external_name_ignoring_case(self):
        s = self.gather_logs("QConsole-User", ["qconsole-user"])
        self.assertRegex(s, r"\*\*PASS\*\* \| Group values of alice map to MarkLogic roles \| `QConsole-User` -> reader \(external name `qconsole-user`: matches ignoring case\)")
        self.assertNotIn("| **FAIL** | Group values of alice", s)

    def test_a_near_miss_names_the_closest_role_external_name(self):
        s = self.gather_logs("qconsole-user", ["qconsole-users"])
        self.assertRegex(s, r"\*\*FAIL\*\* \| Group values of alice map to a MarkLogic role")
        self.assertIn("Closest role external name(s) among the", s)
        self.assertIn("`qconsole-users`", s)
        self.assertIn("case does not matter", s)

    def test_an_unrelated_group_value_gets_no_closest_name(self):
        s = self.gather_logs("finance", ["qconsole-user"])
        self.assertRegex(s, r"\*\*FAIL\*\* \| Group values of alice map to a MarkLogic role")
        self.assertNotIn("Closest role external name", s)

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


# ---------------------------------------------------------------- certificate area (client certificate authentication)
CPORT = 18097
CSTATE = {}


class CertHandler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def reply(self, obj):
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(obj).encode())

    def do_GET(self):
        p = self.path.split("?")[0]
        pems = CSTATE["pems"]
        if p == "/manage/v2":
            return self.reply({"local-cluster-default": {"version": "11.3.7", "name": "mock"}})
        if p == "/manage/v2/hosts":
            return self.reply({"x": {"status-list-items": {"status-list-item": [{"nameref": "h1"}]}}})
        if p == "/manage/v2/servers":
            return self.reply({"x": {"list-items": {"list-item": [{"nameref": "cert-srv", "groupnameref": "Default"}, {"nameref": "other-srv", "groupnameref": "Default"}]}}})
        if p == "/manage/v2/servers/cert-srv/properties":
            d = {"port": 9301, "authentication": "certificate", "internal-security": True, "ssl-certificate-template": CSTATE.get("tpl", "T"),
                 "ssl-require-client-certificate": CSTATE.get("require", True), "ssl-client-issuer-authority-verification": CSTATE.get("verification", False),
                 **({"ssl-min-allow-tls": CSTATE["min_tls"]} if CSTATE.get("min_tls") else {}), **CSTATE.get("tls_flags", {}),
                 "ssl-client-certificate-pem": [pems[k] for k in CSTATE.get("sel", ["root", "inter"])]}
            if CSTATE.get("ext_sec", True):
                d["external-security"] = ["cert-prof"]
            return self.reply(d)
        if p == "/manage/v2/servers/other-srv/properties":
            return self.reply({"port": 9302, "authentication": "digest", "ssl-certificate-template": "T"})
        if p == "/manage/v2/external-security/cert-prof/properties":
            d = {"external-security-name": "cert-prof", "authentication": "certificate", "authorization": CSTATE.get("authz", "internal"), "cache-timeout": 300}
            if CSTATE.get("authz") == "ldap" or CSTATE.get("ldap_settings"):
                d["ldap-server"] = {"ldap-server-uri": CSTATE.get("ldap_uri", "ldap://ldap.example.com:389"), "ldap-base": "dc=example,dc=com", "ldap-attribute": CSTATE.get("ldap_attr", "uid"),
                                    "ldap-default-user": "uid=search,ou=services,dc=example,dc=com", "ldap-password": "SECRETPW", "ldap-start-tls": True}
            return self.reply(d)
        if p == "/manage/v2/roles":
            return self.reply({"x": {"list-items": {"list-item": [{"nameref": "grp-role"}]}}})
        if p == "/manage/v2/roles/grp-role/properties":
            return self.reply({"role-name": "grp-role", "external-name": CSTATE.get("role_dns", [])})
        if p == "/manage/v2/certificate-templates/T":
            return self.reply({"certificate-template-default": {"id": "1", "template-name": "T", "template-version": "1", "key-type": "rsa", "generate-temp-certificate": "false"}})
        if p == "/manage/v2/groups/Default/properties":
            return self.reply({"group-name": "Default", "events-activated": True, "event": ["External Authenticate"]})
        if p == "/manage/v2/logs":
            body = CSTATE.get("errlog", "") if "ErrorLog" in self.path else CSTATE.get("access", "")
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(body.encode())
            return
        if p == "/manage/v2/users":
            return self.reply({"x": {"list-items": {"list-item": [{"nameref": "u1"}, {"nameref": "u2"}] + ([{"nameref": CSTATE["cn_user"]}] if CSTATE.get("cn_user") else [])}}})
        if CSTATE.get("cn_user") and p == "/manage/v2/users/%s/properties" % CSTATE["cn_user"]:
            return self.reply({"user-name": CSTATE["cn_user"], "role": ["reader"], "external-name": []})
        if p == "/manage/v2/users/u1/properties":
            return self.reply({"user-name": "u1", "role": ["reader"], "external-name": ["CN=user1.example.com,OU=TEST ONLY"]})
        if p == "/manage/v2/users/u2/properties":
            return self.reply({"user-name": "u2", "role": ["reader"], "external-name": ["cn-only.example.com"]})
        self.send_response(404)
        self.end_headers()


class CertificateAreaTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="cert-test.")
        T = cls.tmp

        def ossl(*args):
            subprocess.run(["openssl"] + list(args), capture_output=True, check=True, cwd=T)

        def ca(name, issuer=None):
            ossl("req", "-new", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-keyout", name + ".key", "-out", name + ".csr", "-subj", "/CN=" + name)
            Path(T, name + ".ext").write_text("basicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid\n")
            if issuer:
                ossl("x509", "-req", "-in", name + ".csr", "-CA", issuer + ".pem", "-CAkey", issuer + ".key", "-CAcreateserial", "-out", name + ".pem", "-days", "30", "-extfile", name + ".ext")
            else:
                ossl("x509", "-req", "-in", name + ".csr", "-signkey", name + ".key", "-out", name + ".pem", "-days", "30", "-extfile", name + ".ext")

        def leaf(name, subj, issuer, eku="clientAuth", times=None, days="30"):
            ossl("req", "-new", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-keyout", name + ".key", "-out", name + ".csr", "-subj", subj)
            Path(T, name + ".ext").write_text("basicConstraints=CA:FALSE\nkeyUsage=digitalSignature\nextendedKeyUsage=%s\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid\n" % eku)
            args = ["x509", "-req", "-in", name + ".csr", "-CA", issuer + ".pem", "-CAkey", issuer + ".key", "-CAcreateserial", "-out", name + ".pem", "-extfile", name + ".ext"]
            args += (["-not_before", times[0], "-not_after", times[1]] if times else ["-days", days])
            ossl(*args)

        ca("Test-Root")
        ca("Test-Intermediate", "Test-Root")
        ca("Other-Root")
        leaf("user1", "/CN=user1.example.com/OU=TEST ONLY", "Test-Intermediate")
        leaf("serveronly", "/CN=user1.example.com/OU=TEST ONLY", "Test-Intermediate", eku="serverAuth")
        leaf("expired", "/CN=user1.example.com/OU=TEST ONLY", "Test-Intermediate", times=("20200101000000Z", "20200102000000Z"))
        leaf("cnonly", "/CN=cn-only.example.com/OU=TEST ONLY", "Test-Intermediate")
        leaf("unmapped", "/CN=nobody.example.com/OU=TEST ONLY", "Test-Intermediate")
        leaf("foreign", "/CN=user1.example.com/OU=TEST ONLY", "Other-Root")
        leaf("ldaporder", "/UID=jdoe/OU=people/DC=example/DC=com", "Test-Intermediate")
        leaf("ldapreversed", "/DC=com/DC=example/OU=people/UID=jdoe", "Test-Intermediate")
        leaf("ldapelsewhere", "/UID=jdoe/OU=people/O=Elsewhere", "Test-Intermediate")
        leaf("extrardn", "/CN=user1.example.com/OU=TEST ONLY/O=Extra", "Test-Intermediate")
        cls.pems = {"root": Path(T, "Test-Root.pem").read_text(), "inter": Path(T, "Test-Intermediate.pem").read_text(), "other": Path(T, "Other-Root.pem").read_text()}
        CSTATE["pems"] = cls.pems
        Path(T, "chain.pem").write_text(cls.pems["inter"] + cls.pems["root"])
        cls.srv = HTTPServer(("127.0.0.1", CPORT), CertHandler)
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls.srv.server_close()

    def setUp(self):
        for k in ("sel", "verification", "ext_sec", "errlog", "authz", "role_dns", "ldap_attr", "tpl", "require", "min_tls", "tls_flags", "ldap_uri", "ldap_settings", "cn_user"):
            CSTATE.pop(k, None)

    def gather(self, cert=None, chain=False, extra=(), probe=False, **state):
        CSTATE.update(state)
        out = tempfile.mkdtemp(prefix="msg-out.", dir=self.tmp)
        args = [sys.executable, "-I", str(SCRIPT), "certificate", "--host", "127.0.0.1", "--port", str(CPORT), "--scheme", "http", "--user", "admin", "--out", out] + ([] if probe else ["--no-probe"])
        if cert:
            args += ["--client-cert", str(Path(self.tmp, cert + ".pem"))]
        if chain:
            args += ["--client-chain", str(Path(self.tmp, "chain.pem"))]
        r = subprocess.run(args + list(extra), env=dict(os.environ, MARKLOGIC_PASS="x"), capture_output=True, text=True, stdin=subprocess.DEVNULL)
        summary = Path(out, "SUMMARY.md")
        return r, (summary.read_text() if summary.exists() else "")

    def test_only_app_servers_with_certificate_authentication_are_checked(self):
        r, s = self.gather()
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("### `cert-srv`", s)
        self.assertNotIn("other-srv", s)
        self.assertIn("no --client-cert given", s)

    def test_a_working_certificate_passes_issuer_selection_and_maps_to_a_user(self):
        r, s = self.gather("user1", chain=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertRegex(s, r"\*\*PASS\*\* \| cert-srv: every CA up to the root is selected")
        self.assertRegex(s, r"\*\*PASS\*\* \| client certificate DN is the external name of a MarkLogic user \| `CN=user1.example.com,OU=TEST ONLY` -> u1")
        self.assertIn("Subject DN as MarkLogic logs and compares it (the order stored in the certificate, comma, no space): `CN=user1.example.com,OU=TEST ONLY`", s)
        self.assertIn("RFC 2253 order (openssl reverses it): `OU=TEST ONLY,CN=user1.example.com`", s)

    def test_intermediate_only_fails_with_verification_false_and_passes_with_true(self):
        r, s = self.gather("user1", sel=["inter"], verification=False)
        self.assertRegex(s, r"\*\*FAIL\*\* \| cert-srv: every CA up to the root is selected")
        self.assertIn("`CN=Test-Root`", s)
        r, s = self.gather("user1", sel=["inter"], verification=True)
        self.assertRegex(s, r"\*\*PASS\*\* \| cert-srv: client certificate issuer is a selected client CA")
        self.assertNotIn("every CA up to the root", s)

    def test_root_only_or_an_unselected_issuer_fails(self):
        r, s = self.gather("user1", chain=True, sel=["root"])
        self.assertRegex(s, r"\*\*FAIL\*\* \| cert-srv: client certificate issuer is a selected client CA")
        self.assertIn("A CA higher in the chain", s)
        r, s = self.gather("foreign", sel=["root", "inter"])
        self.assertRegex(s, r"\*\*FAIL\*\* \| cert-srv: client certificate issuer is a selected client CA")
        self.assertIn("TLS alert 48", s)

    def test_expired_and_server_only_certificates_are_named(self):
        r, s = self.gather("expired")
        self.assertRegex(s, r"\*\*FAIL\*\* \| client certificate #1 expired")
        self.assertIn("TLS alert 45", s)
        r, s = self.gather("serveronly")
        self.assertRegex(s, r"\*\*FAIL\*\* \| client certificate: extended key usage allows client authentication")
        self.assertIn("TLS alert 43", s)

    def test_cn_only_external_name_and_unmapped_dn_are_told_apart(self):
        r, s = self.gather("cnonly")
        self.assertIn("which is only the CN", s)
        self.assertIn("MarkLogic maps by the FULL subject DN", s)
        r, s = self.gather("unmapped")
        self.assertIn("no user has the external name `CN=nobody.example.com,OU=TEST ONLY`", s)

    def test_no_selected_ca_and_no_external_security_are_failures(self):
        r, s = self.gather(sel=[], ext_sec=False)
        self.assertRegex(s, r"\*\*FAIL\*\* \| cert-srv: a client certificate authority is selected")
        self.assertRegex(s, r"\*\*WARN\*\* \| cert-srv: an external security profile is set")
        self.assertIn("externalAuthenticate failed because no external security is configured", s)

    def test_without_a_profile_the_user_is_found_by_the_cn(self):
        r, s = self.gather("user1", ext_sec=False)
        self.assertRegex(s, r"\*\*FAIL\*\* \| client certificate CN is the name of a MarkLogic user")
        self.assertIn("no user is named `user1.example.com`", s)
        self.assertNotIn("is the external name of a MarkLogic user", s)
        r, s = self.gather("user1", ext_sec=False, cn_user="user1.example.com")
        self.assertRegex(s, r"\*\*PASS\*\* \| client certificate CN is the name of a MarkLogic user")
        self.assertIn("`user1.example.com` (roles: reader)", s)

    def test_a_private_key_is_refused(self):
        key = Path(self.tmp, "user1.key")
        r, s = self.gather(extra=["--client-cert", str(key)])
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("contains a private key", r.stderr)
        self.assertNotIn("BEGIN", s)

    def test_tls_alerts_are_explained_because_nothing_is_logged(self):
        r, s = self.gather()
        self.assertIn("48 unknown ca", s)
        self.assertIn("116 certificate required (TLS 1.3, MarkLogic 12)", s)
        self.assertIn("nothing is written to the ErrorLog or AccessLog", s)

    LOGWIN = ["--logs", "--start", "2026-10-25T09:00:00Z", "--end", "2026-10-25T11:00:00Z"]

    def test_no_log_lines_for_a_tls_rejection_are_information_not_a_warning(self):
        r, s = self.gather("expired", extra=self.LOGWIN)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertRegex(s, r"\*\*INFO\*\* \| no certificate login lines in the ErrorLog window")
        self.assertNotIn("lines found in the ErrorLog window | none: trace events off", s)

    def test_a_no_user_log_line_gets_the_full_dn_hint(self):
        r, s = self.gather("unmapped", extra=self.LOGWIN, errlog=(
            "2026-10-25 10:00:08.000 Info: [Event:id=External Authenticate] ExternalSecurity[cert-prof] certificateAuthenticate() fail because no user\n"
            "2026-10-25 10:00:08.001 Info: [Event:id=External Authenticate] External authentication failed: user= dn=CN=nobody.example.com,OU=TEST ONLY\n"))
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertRegex(s, r"\*\*FAIL\*\* \| CERTIFICATE error, first at 2026-10-25 10:00:08.000")
        self.assertIn("full subject DN shown in `dn=`", s)
        self.assertIn("dn=CN=nobody.example.com,OU=TEST ONLY", s)

    # ---- certificate + authorization ldap
    def test_ldap_authorization_shows_the_search_dn_and_the_command_and_no_password(self):
        r, s = self.gather("ldaporder", chain=True, authz="ldap", role_dns=["cn=grp,ou=groups,dc=example,dc=com"])
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("authorization `ldap`", s)
        self.assertIn("DN used as the search base (stored order): `UID=jdoe,OU=people,DC=example,DC=com`", s)
        self.assertIn('ldapsearch -x -ZZ -H ldap://ldap.example.com:389 -D "uid=search,ou=services,dc=example,dc=com" -W -b "UID=jdoe,OU=people,DC=example,DC=com" -s base uid memberOf', s)
        self.assertRegex(s, r"\*\*PASS\*\* \| CertProfile: certificate DN is under ldap-base|\*\*PASS\*\* \| cert-prof: certificate DN is under ldap-base")
        self.assertNotIn("Mapping the subject DN to a MarkLogic user", s)
        self.assertIn("One log line, four causes", s)
        self.assertNotIn("SECRETPW", s)
        self.assertRegex(s, r"\*\*PASS\*\* \| cert-prof: a role external name is a group DN")
        self.assertRegex(s, r"\*\*INFO\*\* \| cert-prof: LDAP results are cached")

    def test_a_reversed_certificate_dn_is_the_lead_for_unknown_user(self):
        r, s = self.gather("ldapreversed", chain=True, authz="ldap", role_dns=["cn=grp,ou=groups,dc=example,dc=com"])
        self.assertRegex(s, r"\*\*FAIL\*\* \| cert-prof: certificate DN is stored general-first \(reversed\)")
        self.assertIn("DC=com,DC=example,OU=people,UID=jdoe", s)
        self.assertIn("have the CA issue the certificate with the DN in directory order", s)

    def test_a_dn_outside_ldap_base_is_a_warning_and_internal_authorization_still_maps_users(self):
        r, s = self.gather("ldapelsewhere", chain=True, authz="ldap")
        self.assertRegex(s, r"\*\*INFO\*\* \| cert-prof: certificate DN is not under ldap-base `dc=example,dc=com`")
        self.assertIn("ldap-base is not used for a certificate lookup", s)
        r, s = self.gather("user1", chain=True, authz="internal")
        self.assertIn("Mapping the subject DN to a MarkLogic user", s)
        self.assertNotIn("four causes", s)

    def test_an_attribute_the_uid_entry_may_lack_is_a_lead(self):
        r, s = self.gather("ldaporder", chain=True, authz="ldap", ldap_attr="sAMAccountName")
        self.assertRegex(s, r"\*\*WARN\*\* \| cert-prof: ldap-attribute `sAMAccountName` while the certificate DN starts with uid=")
        r, s = self.gather("ldaporder", chain=True, authz="ldap", ldap_attr="uid")
        self.assertNotIn("while the certificate DN starts with uid=", s)

    def test_the_ldap_settings_note_leads_the_no_user_failure(self):
        r, s = self.gather("unmapped", chain=True, ldap_settings=True)
        row = next(l for l in s.splitlines() if l.startswith("| **FAIL** | client certificate DN is the external name"))
        self.assertLess(row.index("has LDAP server settings but authorization `internal`"), row.index("No user has the external name"))

    def test_an_unresolvable_ldap_host_and_a_closed_port_are_named(self):
        r, s = self.gather("ldaporder", chain=True, probe=True, authz="ldap", ldap_uri="ldap://no-such-host.invalid:389", role_dns=["cn=g,dc=example,dc=com"])
        self.assertRegex(s, r"\*\*FAIL\*\* \| cert-prof: the LDAP host name resolves")
        r, s = self.gather("ldaporder", chain=True, probe=True, authz="ldap", ldap_uri="ldap://127.0.0.1:9", role_dns=["cn=g,dc=example,dc=com"])
        self.assertRegex(s, r"\*\*FAIL\*\* \| cert-prof: the LDAP server answers on 127.0.0.1:9")
        self.assertIn("Check the port in ldap-server-uri", s)

    def test_ldap_settings_with_authorization_internal_are_named_when_no_user_matches(self):
        r, s = self.gather("unmapped", chain=True, ldap_settings=True)
        self.assertRegex(s, r"\*\*INFO\*\* \| cert-prof: LDAP settings are present but authorization is internal")
        self.assertIn("has LDAP server settings but authorization `internal`", s)

    def test_a_role_near_miss_warning_about_ldap_base_ranks_last_in_the_conclusion(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location("gather", SCRIPT)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        text = "\n".join(mod.conclusion_lines([("WARN", "p: a role external name is a group DN that looks like ldap-base `x` with another suffix", "other lab role."),
                                               ("WARN", "p: the LDAP connection is not encrypted", "clear text.")], [], []))
        self.assertIn("look at: p: the LDAP connection is not encrypted**", text)

    def test_unknown_user_with_ldap_authorization_gets_its_own_hint(self):
        win = ["--logs", "--start", "2026-10-25T09:00:00Z", "--end", "2026-10-25T11:00:00Z"]
        r, s = self.gather("ldapreversed", chain=True, extra=win, authz="ldap", errlog=(
            "2026-10-25 10:00:08.000 Info: [Event:id=External Authenticate] ExternalSecurity[cert-prof] certificateAuthenticate() fail because unknown user, dn DC=com,DC=example,OU=people,UID=jdoe\n"
            "2026-10-25 10:00:08.001 Info: [Event:id=LDAP] LDAP user DC=com,DC=example,OU=people,UID=jdoe not found in ldapUserCache\n"
            "2026-10-25 10:00:09.000 Error: LDAPClient: XDMP-LDAP-INVALID-CRED: ldap_simple_bind_s failed on ldap server ldap://ldap.example.com:389: Invalid credentials (49)\n"))
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("NOT the internal-authorization `no user`", s)
        self.assertIn("Four causes write this same line", s)
        self.assertIn("wrong password (or DN) of the search account", s)

    def test_an_extra_rdn_in_the_certificate_dn_is_named(self):
        r, s = self.gather("extrardn", chain=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertRegex(s, r"\*\*FAIL\*\* \| client certificate DN is the external name of a MarkLogic user \| no user has the external name")
        self.assertIn("the DN has the extra RDN(s) `O=Extra` that the external name `CN=user1.example.com,OU=TEST ONLY` (user u1) lacks", s)

    def test_a_certificate_that_is_not_required_and_a_tls_13_only_server_are_reported(self):
        r, s = self.gather("user1", chain=True, require=False, min_tls="TLSv1.3")
        self.assertRegex(s, r"\*\*INFO\*\* \| cert-srv: a client certificate is not required")
        self.assertRegex(s, r"\*\*WARN\*\* \| cert-srv: only TLS 1.3 is allowed")
        self.assertIn("fails the handshake and nothing is written to the logs", s)
        r, s = self.gather("user1", chain=True, require=True, min_tls="TLSv1.2")
        self.assertNotIn("only TLS 1.3 is allowed", s)
        self.assertNotIn("a client certificate is not required", s)

    def test_on_marklogic_11_disabling_tls_12_leaves_no_usable_tls_version(self):
        flags = {"ssl-disable-sslv3": True, "ssl-disable-tlsv1": True, "ssl-disable-tlsv1-1": True, "ssl-disable-tlsv1-2": True}
        r, s = self.gather("user1", chain=True, tls_flags=flags)
        self.assertRegex(s, r"\*\*FAIL\*\* \| cert-srv: no TLS version is usable")
        self.assertIn("MarkLogic 11.3.7 does not serve TLS 1.3", s)
        r, s = self.gather("user1", chain=True, tls_flags=dict(flags, **{"ssl-disable-tlsv1-2": False}))
        self.assertNotIn("no TLS version is usable", s)

    def test_new_certificate_log_hints(self):
        win = ["--logs", "--start", "2026-10-25T09:00:00Z", "--end", "2026-10-25T11:00:00Z"]
        r, s = self.gather("user1", chain=True, extra=win, errlog=(
            "2026-10-25 10:00:08.000 Info: [Event:id=External Authenticate] ExternalSecurity[cert-prof] fail because external name\n"
            "2026-10-25 10:00:09.000 Info: [Event:id=External Authenticate] ExternalSecurity[cert-prof] fail because no client certificate\n"))
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("compared case-sensitively, unlike role external names", s)
        self.assertIn("the line appears when a certificate is optional", s)

    def test_without_https_the_missing_certificate_template_is_the_failure_named(self):
        r, s = self.gather(sel=[], tpl=None)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertRegex(s, r"\*\*FAIL\*\* \| cert-srv: HTTPS enabled")
        self.assertNotIn("a client certificate authority is selected", s)
        self.assertIn("**Root cause to look at first: cert-srv: HTTPS enabled**", s)

    def test_a_certificate_login_that_passed_and_then_got_403_is_explained(self):
        win = ["--logs", "--start", "2026-10-25T09:00:00Z", "--end", "2026-10-25T11:00:00Z"]
        CSTATE["access"] = '203.0.113.9 - jdoe [25/Oct/2026:10:00:09 +0000] "GET /qconsole/ HTTP/1.1" 403 0 - "curl"\n'
        try:
            r, s = self.gather("ldaporder", chain=True, extra=win, authz="ldap", errlog=(
                "2026-10-25 10:00:08.000 Info: [Event:id=External Authenticate] ExternalSecurity[cert-prof] certificateAuthenticate() pass, userid 5, user jdoe, temp true\n"))
        finally:
            CSTATE.pop("access", None)
        self.assertRegex(s, r"\*\*WARN\*\* \| certificate login passed, then the request was refused \(403\)")

    def test_the_ca_names_a_server_advertises_are_parsed(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location("gather", SCRIPT)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        txt = ("---\nAcceptable client certificate CA names\nCN=Test-Intermediate\nCN=Test-Root\nRequested Signature Algorithms: ECDSA+SHA256\nShared Requested Signature Algorithms: x\n")
        self.assertEqual(mod.parse_ca_names(txt), ["CN=Test-Intermediate", "CN=Test-Root"])
        self.assertEqual(mod.parse_ca_names("No client certificate CA names sent\n"), [])

    def test_the_trace_script_has_a_certificate_preset(self):
        out = subprocess.run([sys.executable, "-I", str(SCRIPT.parent / "ml-trace-events.py"), "enable", "--help"], capture_output=True, text=True).stdout
        self.assertIn("certificate", out)


if __name__ == "__main__":
    unittest.main()
