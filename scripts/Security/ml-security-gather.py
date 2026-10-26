#!/usr/bin/env python3
"""Collect and sanity-check the security configuration of a MarkLogic cluster for a support case.

  ml-security-gather.py AREA [options]        AREA is one of: saml, oauth, ldap, https
  ml-security-gather.py AREA --help           the options and examples of one area

Areas
  saml    SAML external security profile: settings, IdP certificate, IdP metadata, captured SAML response, role mapping
  oauth   OAuth external security profile (Resource server; Authorization code on MarkLogic 12): settings, IdP discovery
          document and JWKS, IdP TLS chain and trust, captured access token (signature, issuer, claims)
  ldap    LDAP external security profile: settings, certificates, TLS of the directory server, user/role external names
  https   HTTPS app server: TLS settings, certificate template, the certificate chain the port really serves, protocols

Read-only. Uses the Management API (port 8002) with curl and openssl; python3 standard library only. Run it as a MarkLogic
user with the admin role: the user `admin` or any other administrator account (--user NAME, or MARKLOGIC_USER). Works on
MarkLogic 11 and 12 (the report says where the versions differ). Only --host and --user
are required: anything else that is left out is skipped and listed under "Not collected" in SUMMARY.md, with the option
that would add it.

  export MARKLOGIC_PASS='...'      # the password is never taken from the command line
                                   # (if it is not set and a terminal is attached, the script asks for it)

Output: ./<area>-gather-<timestamp>/ with SUMMARY.md, the raw JSON of each call and a .zip of it. Review SUMMARY.md
before sending; it contains host names, entity IDs, certificate details and user names. Passwords, private keys and
client secrets are removed before anything is written. Nothing is changed on the server.

Examples
  ml-security-gather.py saml  --host ml1.example.com --user admin --external-security <profile>
  ml-security-gather.py oauth --host ml1.example.com --user admin --external-security <profile> --token token.txt --logs
  ml-security-gather.py ldap  --host ml1.example.com --user admin --external-security <profile> --user-name <user>
  ml-security-gather.py https --host ml1.example.com --user admin --appserver <app server name>
"""

import argparse
import base64
import concurrent.futures
import datetime as dt
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import urllib.parse
import xml.etree.ElementTree as ET

SECRET_KEY_RE = re.compile(r"(private-key|password|secret|passphrase)", re.I)
PEM_RE = re.compile(r"-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----", re.S)
PRIV_RE = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.S)
NOW = dt.datetime.now(dt.timezone.utc)

REPORT = []   # markdown lines
NOT_COLLECTED = []   # (what, why, how to add it)
CHECKS = []   # (result, name, detail)



# ---------------------------------------------------------------- helpers
def say(line=""):
    REPORT.append(line)


def missing(what, why, how):
    NOT_COLLECTED.append((what, why, how))


def check(result, name, detail=""):
    CHECKS.append((result, name, detail))


def walk(obj):
    """Yield (key, value) for every dict entry in a nested JSON structure."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield k, v
            yield from walk(v)
    elif isinstance(obj, list):
        for v in obj:
            yield from walk(v)


def find_all(obj, *keys):
    out = []
    for k, v in walk(obj):
        if k in keys:
            out.extend(flatten(v))
    return out


def flatten(v):
    if isinstance(v, list):
        r = []
        for x in v:
            r.extend(flatten(x))
        return r
    if isinstance(v, dict):
        r = []
        for x in v.values():
            r.extend(flatten(x))
        return r
    return [] if v is None else [v]


def first(obj, *keys, default=None):
    vals = find_all(obj, *keys)
    return vals[0] if vals else default


def list_names(data):
    """Names in a Management API list response: only the list items (other 'nameref' values point at related objects)."""
    out = set()
    for k, v in walk(data or {}):
        if k in ("list-item", "status-list-item"):
            for it in (v if isinstance(v, list) else [v]):
                if isinstance(it, dict) and "nameref" in it:
                    out.add(str(it["nameref"]))
    return sorted(out)


def redact(obj):
    if isinstance(obj, dict):
        return {k: ("<removed>" if SECRET_KEY_RE.search(k) else redact(v)) for k, v in obj.items()}
    if isinstance(obj, list):
        return [redact(x) for x in obj]
    if isinstance(obj, str):
        return PRIV_RE.sub("<private key removed>", obj)
    return obj


class Api:
    def __init__(self, a):
        self.a = a
        self.password = os.environ.get("MARKLOGIC_PASS")
        if self.password is None:
            sys.exit("ERROR: set the MARKLOGIC_PASS environment variable (passwords are not accepted on the command line)")

    def get(self, path, text=False):
        a = self.a
        url = "%s://%s:%s%s" % (a.scheme, a.host, a.port, path)
        cmd = ["curl", "-sS", "--anyauth", "-K", "-", "-w", "\n%{http_code}", "-H",
               "Accept: */*" if text else "Accept: application/json", "--max-time", "180" if text else "60"]
        if a.cacert:
            cmd += ["--cacert", a.cacert]
        if a.insecure:
            cmd.append("-k")
        cmd.append(url)
        esc = lambda s: s.replace("\\", "\\\\").replace('"', '\\"')
        r = subprocess.run(cmd, input='user = "%s:%s"\n' % (esc(a.user), esc(self.password)),
                           capture_output=True, text=True)
        if r.returncode != 0:
            return None, "curl error %d: %s" % (r.returncode, r.stderr.strip())
        body, _, code = r.stdout.rpartition("\n")
        if code != "200":
            return None, "HTTP %s: %s" % (code, body[:200].replace("\n", " "))
        if text:
            return body, None
        try:
            return json.loads(body), None
        except ValueError:
            return None, "response was not JSON"


def q(s):
    return urllib.parse.quote(str(s), safe="")


# ---------------------------------------------------------------- certificates
def split_certs(text):
    """Return a list of DER byte strings from a PEM bundle (or bare base64)."""
    if not text:
        return []
    blocks = PEM_RE.findall(text)
    if not blocks and "BEGIN" not in text:
        blocks = [text]
    out = []
    for b in blocks:
        try:
            out.append(base64.b64decode(re.sub(r"\s+", "", b)))
        except Exception:
            pass
    return out


def der_to_pem(der):
    b = base64.b64encode(der).decode()
    return "-----BEGIN CERTIFICATE-----\n" + "\n".join(b[i:i + 64] for i in range(0, len(b), 64)) + "\n-----END CERTIFICATE-----\n"


def openssl(args, data=None):
    try:
        r = subprocess.run(["openssl"] + args, input=data, capture_output=True, text=True)
    except OSError as e:
        return 127, str(e)
    return r.returncode, r.stdout + r.stderr


def parse_dt(s):
    try:
        return dt.datetime.strptime(s.strip(), "%b %d %H:%M:%S %Y %Z").replace(tzinfo=dt.timezone.utc)
    except ValueError:
        return None


def cert_info(der):
    pem = der_to_pem(der)
    info = {"sha1": ":".join("%02X" % b for b in hashlib.sha1(der).digest()),
            "sha256": ":".join("%02X" % b for b in hashlib.sha256(der).digest()), "pem": pem}
    rc, out = openssl(["x509", "-noout", "-nameopt", "RFC2253", "-subject", "-issuer", "-serial", "-startdate",
                       "-enddate", "-text"], pem)
    if rc != 0:
        info["error"] = out.strip()[:200]
        return info
    for line in out.splitlines():
        s = line.strip()
        for key, name in (("subject=", "subject"), ("issuer=", "issuer"), ("serial=", "serial")):
            if s.startswith(key):
                info[name] = s[len(key):].strip()
        if s.startswith("notBefore="):
            info["not_before"] = parse_dt(s[10:])
        if s.startswith("notAfter="):
            info["not_after"] = parse_dt(s[9:])
        if s.startswith("Signature Algorithm:") and "sigalg" not in info:
            info["sigalg"] = s.split(":", 1)[1].strip()
        m = re.search(r"Public-Key: \((\d+) bit\)", s)
        if m:
            info["bits"] = int(m.group(1))
        m2 = re.search(r"Public Key Algorithm: (\S+)", s)
        if m2:
            info["keyalg"] = m2.group(1)
        if s.startswith("CA:"):
            info["ca"] = s.startswith("CA:TRUE")
    lines = out.splitlines()
    for n, line in enumerate(lines):
        if "X509v3 Subject Key Identifier" in line and n + 1 < len(lines):
            info["ski"] = lines[n + 1].strip().upper()
        if "X509v3 Authority Key Identifier" in line and n + 1 < len(lines):
            info["aki"] = lines[n + 1].strip().replace("keyid:", "").upper()
    info["self_signed"] = info.get("subject") == info.get("issuer")
    return info


def verify_signed_by(der, issuer_der):
    with tempfile.TemporaryDirectory() as d:
        c, i = os.path.join(d, "c.pem"), os.path.join(d, "i.pem")
        open(c, "w").write(der_to_pem(der))
        open(i, "w").write(der_to_pem(issuer_der))
        rc, out = openssl(["verify", "-no-CApath", "-partial_chain", "-CAfile", i, c])
    if "unknown option" in out.lower() or "usage" in out.lower():
        return None, "this openssl does not support the options needed"
    if re.search(r"error \d+ at \d+ depth lookup: certificate has expired|has expired", out):
        # the signature was checked before the dates; treat expiry as a separate finding
        return True, "signature ok (certificate expired)"
    return rc == 0 and out.strip().endswith("OK"), out.strip().splitlines()[-1] if out.strip() else ""


def fmt_dt(d):
    return d.strftime("%Y-%m-%d") if d else "?"


def analyse_chain(label, pem_text, issuer_note=None):
    """Describe a PEM bundle and say whether the chain is complete. Returns the list of cert infos."""
    ders = split_certs(pem_text)
    say("#### %s" % label)
    if not ders:
        say("No certificate found in the value (empty or not PEM).")
        check("FAIL", label + " present", "no certificate stored")
        return []
    infos = [cert_info(d) for d in ders]
    say("| # | Subject | Issuer | Valid | Expires in | SHA-1 | Sig / key | CA |")
    say("|---|---|---|---|---|---|---|---|")
    for n, i in enumerate(infos, 1):
        left = (i["not_after"] - NOW).days if i.get("not_after") else None
        say("| %d | `%s` | `%s` | %s to %s | %s | `%s` | %s / %s | %s |" % (
            n, i.get("subject", "?"), i.get("issuer", "?"), fmt_dt(i.get("not_before")), fmt_dt(i.get("not_after")),
            ("EXPIRED" if left is not None and left < 0 else "%s days" % left), i["sha1"],
            i.get("sigalg", "?"), i.get("bits", "?"), {True: "yes", False: "no"}.get(i.get("ca"), "n/a")))
        if i.get("not_after") and left < 0:
            check("FAIL", "%s #%d expired" % (label, n), "expired %s" % fmt_dt(i["not_after"]))
        elif i.get("not_after") and left < 30:
            check("WARN", "%s #%d expires soon" % (label, n), "%d days left" % left)
        if i.get("not_before") and i["not_before"] > NOW:
            check("FAIL", "%s #%d not yet valid" % (label, n), "valid from %s" % fmt_dt(i["not_before"]))
        if i.get("sigalg") and "sha1" in i["sigalg"].lower():
            check("WARN", "%s #%d uses SHA-1 signature" % (label, n), i["sigalg"])
        if i.get("bits") and i["bits"] < 2048 and str(i.get("keyalg", "rsaEncryption")).startswith("rsa"):
            check("WARN", "%s #%d key is %d bits" % (label, n, i["bits"]))
    # chain walk: each certificate needs its issuer in the bundle unless it is self-signed
    problems = []
    for n, (der, i) in enumerate(zip(ders, infos), 1):
        if i.get("self_signed"):
            ok, why = verify_signed_by(der, der)
            say("- #%d is self-signed (it is its own trust anchor); signature check: %s" % (
                n, "ok" if ok else ("not run" if ok is None else "FAILED: " + why)))
            if ok is False:
                problems.append("#%d self-signature does not verify" % n)
            continue
        issuers = [(k, d) for k, (d, x) in enumerate(zip(ders, infos), 1) if x.get("subject") == i.get("issuer") and d is not der]
        if not issuers:
            say("- #%d is issued by `%s`, which is **not in the stored bundle**." % (n, i.get("issuer")))
            problems.append("#%d issuer `%s` missing" % (n, i.get("issuer")))
            continue
        k, idr = issuers[0]
        ok, why = verify_signed_by(der, idr)
        say("- #%d is issued by #%d; signature check: %s" % (n, k, "ok" if ok else ("not run" if ok is None else "FAILED: " + why)))
        if ok is False:
            problems.append("#%d not signed by #%d" % (n, k))
    roots = [i for i in infos if i.get("self_signed")]
    hard = [x for x in problems if "missing" not in x]
    if hard:
        check("FAIL", label + " chain valid", "; ".join(hard))
    elif problems:
        check("INFO", label + " issuer not stored",
              "; ".join(problems) + ". " + (issuer_note or "Informational: a SAML login worked on a 12.1.0 test server (authentik) with only the IdP signing "
              "certificate stored, so MarkLogic does not need the issuer. Match the stored certificate against the IdP metadata instead"))
    elif roots:
        check("PASS", label + " chain complete", "ends in a self-signed certificate (%d in bundle)" % len(infos))
    else:
        check("WARN", label + " chain has no root", "no self-signed certificate in the bundle; fine only if MarkLogic is meant to trust an intermediate")
    say("")
    return infos


# ---------------------------------------------------------------- IdP metadata
def ln(tag):
    return tag.rsplit("}", 1)[-1]


def parse_metadata(text):
    root = ET.fromstring(text)
    md = {"entity_id": None, "sso": [], "certs": [], "valid_until": None, "multiple": False}
    entities = [e for e in root.iter() if ln(e.tag) == "EntityDescriptor"]
    if root.tag and ln(root.tag) == "EntityDescriptor":
        entities = [root]
    md["multiple"] = len(entities) > 1
    if not entities:
        return md
    e = entities[0]
    md["entity_id"] = e.get("entityID")
    md["valid_until"] = e.get("validUntil")
    for idp in [x for x in e.iter() if ln(x.tag) == "IDPSSODescriptor"]:
        for kd in [x for x in idp.iter() if ln(x.tag) == "KeyDescriptor"]:
            if kd.get("use") in (None, "signing"):
                for c in kd.iter():
                    if ln(c.tag) == "X509Certificate" and c.text:
                        md["certs"].append(re.sub(r"\s+", "", c.text))
        for s in idp:
            if ln(s.tag) == "SingleSignOnService":
                md["sso"].append((s.get("Binding", ""), s.get("Location", "")))
    return md


def load_metadata(src, a):
    if re.match(r"https?://", src):
        cmd = ["curl", "-sSL", "--max-time", "30"]
        if a.metadata_insecure:
            cmd.append("-k")
        r = subprocess.run(cmd + [src], capture_output=True, text=True)
        if r.returncode != 0:
            return None, "could not download metadata: " + r.stderr.strip()
        return r.stdout, None
    try:
        return open(src, encoding="utf-8", errors="replace").read(), None
    except OSError as e:
        return None, str(e)


def sha1_of_b64(b64):
    der = base64.b64decode(b64 + "=" * (-len(b64) % 4))
    return ":".join("%02X" % b for b in hashlib.sha1(der).digest())


# ---------------------------------------------------------------- SAML response
def load_response(path):
    raw = open(path, encoding="utf-8", errors="replace").read().strip()
    m = re.search(r"SAML token=\s*([A-Za-z0-9+/=%_-]+)", raw)
    if m:
        raw = m.group(1)
    if "%" in raw and not raw.startswith("<"):
        raw = urllib.parse.unquote(raw)
    if not raw.startswith("<"):
        raw = base64.b64decode(re.sub(r"\s+", "", raw) + "===").decode("utf-8", "replace")
    return raw


def parse_iso(s):
    try:
        return dt.datetime.fromisoformat(s.replace("Z", "+00:00"))
    except Exception:
        return None


def analyse_response(xml_text, cfg, md, ext_names):
    root = ET.fromstring(xml_text)
    nodes = list(root.iter())
    resp_el = root if ln(root.tag) == "Response" else None
    ass = [n for n in nodes if ln(n.tag) == "Assertion"]
    say("## SAML response check")
    say("")
    if not ass:
        say("The response contains no Assertion (the IdP may have returned an error status).")
        status = [n.get("Value") for n in nodes if ln(n.tag) == "StatusCode"]
        check("FAIL", "response contains an assertion", "status: %s" % ", ".join(status or ["?"]))
        return
    a = ass[0]
    issuers = {(n.text or "").strip() for n in nodes if ln(n.tag) == "Issuer"}
    audiences = [(n.text or "").strip() for n in nodes if ln(n.tag) == "Audience"]
    conds = [n for n in nodes if ln(n.tag) == "Conditions"]
    sigs = [n for n in nodes if ln(n.tag) == "Signature"]
    sig_parents = set()
    for p in nodes:
        for c in p:
            if ln(c.tag) == "Signature":
                sig_parents.add(ln(p.tag))
    say("- Issuer(s): %s" % ", ".join("`%s`" % i for i in sorted(issuers)))
    say("- Audience: %s" % ", ".join("`%s`" % x for x in audiences))
    if resp_el is not None:
        say("- Response Destination: `%s`, IssueInstant %s" % (resp_el.get("Destination"), resp_el.get("IssueInstant")))
    say("- Signed elements: %s" % (", ".join(sorted(sig_parents)) or "none"))
    ent, iss = cfg.get("saml-entity-id"), cfg.get("saml-issuer")
    if ent:
        check("PASS" if ent in issuers else "FAIL", "assertion Issuer = saml-entity-id",
              "config `%s` / assertion %s" % (ent, ", ".join(sorted(issuers))))
    if iss:
        check("PASS" if iss in audiences else "FAIL", "assertion Audience = saml-issuer (SP entity ID)",
              "config `%s` / assertion %s" % (iss, ", ".join(audiences) or "none"))
    check("PASS" if "Assertion" in sig_parents else "FAIL", "assertion is signed",
          "MarkLogic requires a signed assertion (tested on 12.1.0); signed elements: %s" % (", ".join(sorted(sig_parents)) or "none"))
    for c in conds:
        nb, na = parse_iso(c.get("NotBefore", "")), parse_iso(c.get("NotOnOrAfter", ""))
        say("- Conditions: NotBefore %s, NotOnOrAfter %s (checked against the time this script ran: %s)" % (
            c.get("NotBefore"), c.get("NotOnOrAfter"), NOW.strftime("%Y-%m-%dT%H:%MZ")))
        say("  (a captured response is normally expired by now; compare with the time of the failed request, not with the time of this check)")
        if nb and na and not nb < na:
            check("FAIL", "Conditions window is valid", "NotBefore is not before NotOnOrAfter")
    embedded = {sha1_of_b64(re.sub(r"\s+", "", n.text)) for n in nodes if ln(n.tag) == "X509Certificate" and n.text}
    for fp in sorted(embedded):
        say("- Signing certificate embedded in the response: SHA-1 `%s`" % fp)
    conf = cfg.get("_cert_sha1", [])
    if embedded and conf:
        check("PASS" if embedded & set(conf) else "FAIL", "response signing cert = certificate stored in MarkLogic",
              "response %s / MarkLogic %s" % (", ".join(sorted(embedded)), ", ".join(conf)))
    if embedded and md and md["certs"]:
        mdfp = {sha1_of_b64(c) for c in md["certs"]}
        check("PASS" if embedded & mdfp else "WARN", "response signing cert is listed in the IdP metadata",
              "metadata lists %d signing certificate(s)" % len(mdfp))
    nameid = next((n.text.strip() for n in nodes if ln(n.tag) == "NameID" and n.text), None)
    attrs = {}
    for n in nodes:
        if ln(n.tag) == "Attribute":
            attrs[n.get("Name", "?")] = [(v.text or "").strip() for v in n if ln(v.tag) == "AttributeValue"]
    say("- NameID: `%s`" % nameid if nameid else "- NameID: none")
    say("- Attribute names: %s" % (", ".join("`%s` (%d value(s))" % (k, len(v)) for k, v in attrs.items()) or "none"))
    if ext_names:
        hits = []
        if nameid and nameid in ext_names["all"]:
            hits.append("NameID matches an external name (%s)" % ", ".join(ext_names["all"][nameid]))
        for k, vals in attrs.items():
            for v in vals:
                if v in ext_names["all"]:
                    hits.append("attribute `%s` value `%s` matches (%s)" % (k, v, ", ".join(ext_names["all"][v])))
        if hits:
            for h in hits:
                say("- Matched: " + h)
            check("PASS", "assertion matches a MarkLogic external name", "; ".join(hits))
        else:
            check("FAIL", "assertion matches a MarkLogic external name",
                  "neither the NameID nor any attribute value equals an external name of the users/roles supplied")
    elif nameid or attrs:
        check("INFO", "external-name mapping not checked", "pass --user-name to compare the assertion with a user's external names")
    say("")


# ---------------------------------------------------------------- logs
TS_ERR = re.compile(r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d+) (\w+): (.*)$")
TS_ACC = re.compile(r"\[(\d{1,2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2} [+-]\d{4})\]")
MAPPED = re.compile(r"External User\((.*?)\) is Mapped to Temp User\((.*?)\) with Role\(s\):(.*)$")
SAML_EVENTS = ("SAML", "SAML Response", "External Authenticate")
ERROR_MSG = re.compile(r"Saml Response Error|SAML signature is invalid|Error: |Cached Response is invalid|not found in SAML XML")
# message pattern -> likely meaning (these are leads, not proof; the matching message is quoted verbatim)
HINTS = [
    (r"signature is invalid|SAML signature is invalid",
     "The signature does not verify with the certificate stored in `saml-idp-certificate-authority`: the IdP is signing with a different (rotated, or per-application) certificate, or the assertion was altered. Compare the stored certificate's SHA-1 with the IdP metadata and with the certificate embedded in the response."),
    (r"Signature node not found", "The assertion arrived unsigned. MarkLogic requires a signed assertion: enable assertion signing at the IdP."),
    (r"Audience .* does not match", "The audience the IdP sets must equal `saml-issuer` (the SP entity ID in MarkLogic)."),
    (r"recipient .* does not match", "The ACS/recipient URL at the IdP differs from the app server URL MarkLogic expects."),
    (r"status .* is not Success", "The IdP returned an error status instead of an assertion; check the IdP's log."),
    (r"cannot parse response", "The value sent after `SAML token=` (or posted as SAMLResponse) is not a base64-encoded SAML Response XML. Check what the application sends (truncated, double-encoded, or not a SAML response)."),
    (r"expected 1 assertion", "The response held no (or several) assertions."),
    (r"Issuer .* does not match configured IdP|Issuer", "The assertion Issuer must equal `saml-entity-id` (the IdP entity ID) exactly, including a trailing slash. Copy the Issuer from this line or from the IdP metadata `entityID`; for Microsoft Entra it is `https://sts.windows.net/<tenant-id>/` (the Microsoft Entra Identifier), not a value made up in the MarkLogic namespace. A valid signature and audience do not make up for it: the login is still refused (HTTP 401)."),
    (r"Expired|NotBefore|notOnOrAfter|expired", "Validity window problem: check clock synchronisation (NTP) on the MarkLogic hosts and the IdP. If the same samlId repeats minutes after the first attempt, the browser is resubmitting an old response: look at the first attempt for the real reason."),
]


def scrub(line):
    line = re.sub(r"((?:SAMLRequest|SAMLResponse|Signature|RelayState)=)[^&\s]+", r"\1<removed>", line)
    line = re.sub(r"(<(?:ds:)?(?:SignatureValue|DigestValue|X509Certificate)>)[^<]*", r"\1<removed>", line)
    # whole tokens: a JWT (header.payload.signature), and the token values of a token-endpoint response
    line = re.sub(r"eyJ[\w-]+\.eyJ[\w-]+\.[\w-]*", "<JWT removed>", line)
    line = re.sub(r'("(?:access_token|refresh_token|id_token)"\s*:\s*")[^"]*', r"\1<removed>", line)
    line = re.sub(r"[A-Za-z0-9+/=%]{120,}", lambda m: "<%d chars removed>" % len(m.group(0)), line)
    return re.sub(r"(?:<JWT removed>|<\d+ chars removed>)\.<\d+ chars removed>\.[\w-]+", "<JWT removed>", line)


def load_role_map(api, out, errors):
    """external name -> [roles], from every role's properties (the Group values of an assertion are matched to these)."""
    data, err = api.get("/manage/v2/roles?format=json")
    if err:
        errors.append("/manage/v2/roles: " + err)
        return None
    names = list_names(data)
    if len(names) > 1500:
        errors.append("roles: %d roles, only the first 1500 were read" % len(names))
        names = names[:1500]
    rmap = {}

    def read_role(n):
        rp, err = api.get("/manage/v2/roles/%s/properties?format=json" % q(n))
        return n, ([] if err else [str(x) for x in find_all(rp, "external-name")])

    # one curl per role: read them in parallel (a cluster can have hundreds of roles)
    with concurrent.futures.ThreadPoolExecutor(max_workers=12) as pool:
        for n, ens in pool.map(read_role, names):
            for en in ens:
                rmap.setdefault(en, []).append(n)
    with open(os.path.join(out, "roles-external-names.json"), "w") as f:
        json.dump(rmap, f, indent=2)
    return rmap


def utc_arg(text):
    """A UTC time for --start / --end: ISO 8601. 'Z' or no zone mean UTC; an offset such as +02:00 is converted to UTC."""
    t = str(text).strip()
    try:
        d = dt.datetime.fromisoformat(t[:-1] + "+00:00" if t[-1:] in ("Z", "z") else t)
    except ValueError:
        raise argparse.ArgumentTypeError(
            "'%s' is not a time this script understands. Give a UTC time such as 2026-01-15T09:00:00Z. Also accepted: 2026-01-15T09:00Z, "
            "2026-01-15 09:00:00, a date (2026-01-15, meaning 00:00), or a time with an offset such as 2026-01-15T10:00:00+01:00 (converted to UTC)" % text)
    if d.tzinfo is None:
        d = d.replace(tzinfo=dt.timezone.utc)
    return d.astimezone(dt.timezone.utc)


def window(a):
    end = a.end if a.end else NOW
    start = a.start if a.start else end - dt.timedelta(minutes=a.minutes)
    return start, end


def iso(d):
    return d.strftime("%Y-%m-%dT%H:%M:%SZ")


def keep_error_lines(text, events=None, pattern=r"saml"):
    events = events or SAML_EVENTS
    kept, cur = [], None
    for raw in text.splitlines():
        m = TS_ERR.match(raw)
        if m:
            ts, level, msg = m.groups()
            ev = re.match(r"\[Event:id=([^\]]+)\]", msg)
            want = (ev and ev.group(1) in events) or re.search(pattern, msg, re.I) or (level in ("Warning", "Error") and "SEC-" in msg)
            cur = [ts, level, msg] if want else None
            if cur:
                kept.append(cur)
        elif cur is not None:
            cur[2] += " " + raw.strip()
    return kept


def analyse_logs(a, api, out, cfgs, bound, hostnames, role_map, errors):
    start, end = window(a)
    say("## Logs (%s to %s UTC)" % (iso(start), iso(end)))
    say("")
    say("Log times are written in each host's local time zone; the window above is UTC. If a host is not on UTC, widen the window or pass --start/--end. The ErrorLog does not say which app server a line belongs to: if several app servers use external security at the same time, reproduce one login at a time (the AccessLog is per app server).")
    say("")
    # trace events on the groups of the bound app servers
    for grp in sorted({g for _, g, _ in bound}):
        gp, err = api.get("/manage/v2/groups/%s/properties?format=json" % q(grp))
        if err:
            errors.append("group %s: %s" % (grp, err))
            continue
        ev = [str(x) for x in find_all(gp, "event")]
        on = bool(first(gp, "events-activated", default=False))
        say("- Trace events, group `%s`: mechanism %s, events: %s" % (grp, "ON" if on else "off", ", ".join(ev) or "none"))
        if not (on and "SAML" in ev):
            check("WARN", "SAML trace events enabled on group %s" % grp,
                  "off: the ErrorLog will not show why a login is rejected. Run ml-trace-events.py enable --preset saml, reproduce, then gather again")
    say("")
    all_msgs, resp_rows, mapped_rows, status_counts, bad_lines = [], [], [], {}, []
    for h in hostnames:
        text, err = api.get("/manage/v2/logs?filename=ErrorLog.txt&host=%s&format=text&start=%s&end=%s" % (q(h), q(iso(start)), q(iso(end))), text=True)
        if err or text.lstrip().startswith("<error"):
            errors.append("ErrorLog on %s: %s" % (h, err or text[:200].replace("\n", " ")))
            continue
        kept = keep_error_lines(text)
        with open(os.path.join(out, "ErrorLog-saml-%s.txt" % re.sub(r"\W+", "_", h)), "w") as f:
            f.write("# ErrorLog lines about SAML / external authentication from %s, %s to %s UTC; long values removed\n" % (h, iso(start), iso(end)))
            for ts, level, msg in kept:
                f.write("%s %s: %s\n" % (ts, level, scrub(msg)))
        say("- ErrorLog on `%s`: %d SAML/authentication line(s) in the window (saved as ErrorLog-saml-*.txt)" % (h, len(kept)))
        for ts, level, msg in kept:
            body = re.sub(r"^\[Event:id=[^\]]+\]\s*", "", msg)
            all_msgs.append((h, ts, body))
            m = re.match(r"Saml Response samlId:(\S*) Username:(\S*) Group:\s*(.*?)\s+Valid from:(\S*) Valid until:(\S*)", body)
            if m and m.group(2):
                resp_rows.append((h, ts) + m.groups())
        for port_srv in {p for _, _, p in bound if p}:
            atext, aerr = api.get("/manage/v2/logs?filename=%s_AccessLog.txt&host=%s&format=text" % (q(port_srv), q(h)), text=True)
            if aerr or atext.lstrip().startswith("<error"):
                errors.append("%s_AccessLog.txt on %s: %s" % (port_srv, h, aerr or atext[:150].replace("\n", " ")))
                continue
            pend = []
            lines_out = []
            for raw in atext.splitlines():
                mm = MAPPED.search(raw)
                if mm:
                    pend.append(mm.groups())
                    continue
                t = TS_ACC.search(raw)
                if not t:
                    continue
                when = dt.datetime.strptime(t.group(1), "%d/%b/%Y:%H:%M:%S %z").astimezone(dt.timezone.utc)
                if start <= when <= end:
                    st = re.search(r'" (\d{3}) ', raw)
                    code = st.group(1) if st else "?"
                    status_counts[(port_srv, code)] = status_counts.get((port_srv, code), 0) + 1
                    for ext, tmp, roles in pend:
                        mapped_rows.append((h, port_srv, iso(when), ext, tmp, [r.strip() for r in roles.split(",") if r.strip()]))
                    if code in ("401", "403") or code.startswith("5"):
                        bad_lines.append((h, port_srv, iso(when), re.sub(r"\?\S*", "?<query removed>", scrub(raw))[:240]))
                    lines_out.append(re.sub(r"\?\S*", "?<query removed>", scrub(raw)))
                pend = []
            with open(os.path.join(out, "AccessLog-%s-%s.txt" % (port_srv, re.sub(r"\W+", "_", h))), "w") as f:
                f.write("# %s_AccessLog.txt from %s, %s to %s UTC (query strings removed)\n" % (port_srv, h, iso(start), iso(end)))
                f.write("\n".join(lines_out[-300:]) + "\n")
            say("- AccessLog `%s_AccessLog.txt` on `%s`: %d request(s) in the window" % (port_srv, h, sum(v for (pp, _), v in status_counts.items() if pp == port_srv)))
    say("")

    saml_lines = [m for m in all_msgs if m[2]]
    if not all_msgs:
        say("No SAML lines in the window.")
        check("WARN", "SAML lines found in the ErrorLog window", "none: trace events off, no login attempt in the window, or a time-zone offset")
    else:
        say("### SAML validation steps seen")
        say("")
        norm = {}
        for h, ts, body in all_msgs:
            k = re.sub(r"c\d{10,}", "<id>", re.sub(r"\d{4}-\d{2}-\d{2}T[\d:]+Z", "<time>", body))[:110]
            norm[k] = norm.get(k, 0) + 1
        say("| Count | Message |")
        say("|---|---|")
        for k, v in sorted(norm.items(), key=lambda kv: -kv[1]):
            if k.startswith("Saml Authn Request:") or k.startswith("Saml Redirect to IDP"):
                k = k[:40] + " ... (XML/URL not shown)"
            say("| %d | %s |" % (v, k.replace("|", "\\|")))
        say("")
        errs = [(h, ts, b) for h, ts, b in all_msgs if ERROR_MSG.search(b) and "Cached Response not found" not in b]
        grouped = {}
        for h, ts, b in errs:
            grouped.setdefault(scrub(b)[:160], []).append(ts)
        for msg, times in list(grouped.items())[:15]:
            hint = next((t for pat, t in HINTS if re.search(pat, msg)), None)
            check("FAIL", "SAML error, first at %s (%d time%s)" % (times[0], len(times), "" if len(times) == 1 else "s"),
                  "`%s`%s" % (msg, (" - " + hint) if hint else ""))
        if errs:
            say("**%d SAML error message(s)**; the first is the one to start from. Quoted in Check results." % len(errs))
        valid = sum(1 for _, _, b in all_msgs if b == "Saml Response is valid")
        passed = sum(1 for _, _, b in all_msgs if re.match(r"ExternalSecurity\[.*\] pass", b))
        say("Responses MarkLogic validated: %d; external authentication passes: %d." % (valid, passed))
        if any(b.startswith("External authentication failed: user=") for _, _, b in all_msgs):
            say("(`External authentication failed: user=` lines with no user name appear for the first request, before a session exists; they are normal.)")
        if valid and not errs:
            check("PASS", "MarkLogic accepted the SAML response", "%d response(s) validated; no SAML error lines" % valid)
        redirects = sum(1 for _, _, b in all_msgs if b.startswith("[Event:id=SAML] Saml Redirect to IDP") or b.startswith("Saml Redirect to IDP"))
        got_response = any("Saml Response samlId:" in b for _, _, b in all_msgs)
        if redirects and not got_response and not errs:
            check("INFO", "browser was sent to the IdP but no SAML response came back",
                  "%d redirect(s) to the IdP and no assertion posted back to MarkLogic in this window: the login stopped at the IdP "
                  "(wrong or denied user, for example an application policy binding in the IdP; a blocked ACS URL), or it happened outside the window or "
                  "before the trace events were switched on. Check the IdP's own log" % redirects)
        say("")

    if resp_rows:
        say("### Identity in the assertion (from the trace) and role mapping")
        say("")
        say("| Time | NameID (Username) | Group values | Valid from / until |")
        say("|---|---|---|---|")
        for h, ts, sid, user, grp, vf, vu in resp_rows[-10:]:
            say("| %s | `%s` | `%s` | %s / %s |" % (ts, user, grp, vf, vu))
        say("")
        auth_modes = {c.get("authorization") for c in cfgs.values()}
        if role_map is not None:
            seen_g = set()
            for h, ts, sid, user, grp, vf, vu in resp_rows:
                if (user, grp) in seen_g:
                    continue
                seen_g.add((user, grp))
                toks = grp.split()
                hit = {t: role_map[t] for t in toks if t in role_map}
                if hit:
                    check("PASS", "Group values of %s map to MarkLogic roles" % user,
                          "; ".join("`%s` -> %s" % (t, ", ".join(r)) for t, r in hit.items()))
                else:
                    check("FAIL", "Group values of %s map to a MarkLogic role" % user,
                          "none of `%s` equals the external-name of any role, so the SAML identity gets no roles" % grp)
            say("With authorization `saml` the assertion's Group values are matched to roles' external names (roles-external-names.json lists them).")
            say("")
    if mapped_rows:
        say("### Roles the SAML identity actually received (AccessLog)")
        say("")
        say("| Time | App server | External user | Temp user | Role(s) |")
        say("|---|---|---|---|---|")
        for h, port_srv, when, ext, tmp, roles in mapped_rows[-15:]:
            say("| %s | %s | `%s` | `%s` | %s |" % (when, port_srv, ext, tmp, ", ".join(roles) or "**none**"))
            if not roles:
                why = ("Mapped to Temp User with empty Role(s): no role has an external name equal to a Group value of the assertion. The MarkLogic user's own roles and external names "
                       "are not used for a SAML login (tested on 11.3.7, with authorization `saml` and with `internal`). Give a role an external name equal to a Group value. "
                       "If the profile or the roles were changed after this time, the result may predate the change")
                check("FAIL", "%s was given roles at %s" % (ext, when), why)
        say("")
    if status_counts:
        say("### HTTP status codes in the window (app server AccessLog)")
        say("")
        for (port_srv, code), v in sorted(status_counts.items()):
            say("- port %s: %s x %d" % (port_srv, code, v))
        say("")
        for h, port_srv, when, line in bad_lines[-8:]:
            say("  - `%s`" % line)
        if any(l[3] for l in bad_lines):
            n403 = sum(1 for l in bad_lines if '" 403 ' in l[3])
            n401 = sum(1 for l in bad_lines if '" 401 ' in l[3])
            if n401:
                check("INFO", "401 responses in the window", "%d: authentication was refused; see the SAML error lines in the ErrorLog" % n401)
            if n403:
                check("INFO", "403 responses in the window", "%d: the SAML login succeeded but the user lacks a privilege or role for the URL. Authorization failures are in the AccessLog, not the ErrorLog; compare the roles above with the privileges the app server needs" % n403)
        say("")


class Parser(argparse.ArgumentParser):
    """Prints the full documentation, then the error, when the command line is wrong."""

    def error(self, message):
        self.print_help(sys.stderr)
        sys.stderr.write("\nERROR: %s\n" % message)
        sys.exit(2)


def explain_connection_failure(a, err):
    hints = []
    if "HTTP 401" in err:
        hints.append("The Management API refused the user name or password. Check --user and the MARKLOGIC_PASS environment variable.")
    elif "HTTP 403" in err:
        hints.append("The user is not allowed to read the configuration. Run the script as a MarkLogic user with the admin role (--user).")
    elif re.search(r"curl error (6|7|28):", err):
        hints.append("Cannot connect. Check --host, --port (the Management API is normally 8002) and --scheme (http or https).")
    elif re.search(r"curl error (35|51|58|60|77):", err):
        hints.append("The TLS certificate of the Management API is not trusted from this machine, or the port does not use TLS. "
                     "Use --cacert <ca.pem> (or --insecure for a one-off test), or --scheme http if the port is not TLS.")
    else:
        hints.append("Check --host, --port and --scheme, and that the Management API is reachable from this machine.")
    sys.stderr.write("ERROR: could not read %s://%s:%s/manage/v2 (%s)\n%s\nRun with --help for all options.\n" % (
        a.scheme, a.host, a.port, err, "\n".join(hints)))
    sys.exit(1)


# ---------------------------------------------------------------- shared by the areas
class Ctx:
    """What every area needs: arguments, API access, output folder, cluster facts."""


def version_tuple(v):
    return tuple(int(x) for x in re.findall(r"\d+", str(v))[:3]) or (0,)


def slug(s):
    return re.sub(r"\W+", "_", str(s))


def setup(a, p, area):
    if os.environ.get("MARKLOGIC_PASS") is None:
        if sys.stdin.isatty():
            import getpass
            os.environ["MARKLOGIC_PASS"] = getpass.getpass("Password for %s: " % a.user)
        else:
            p.error("set the MARKLOGIC_PASS environment variable, for example: export MARKLOGIC_PASS='<password>' "
                    "(passwords are not accepted on the command line)")
    api = Api(a)
    _, err = api.get("/manage/v2?format=json")
    if err:
        explain_connection_failure(a, err)
    out = a.out or "%s-gather-%s" % (area, NOW.strftime("%Y%m%d-%H%M%S"))
    os.makedirs(out, exist_ok=True)
    c = Ctx()
    c.a, c.api, c.out, c.area, c.errors = a, api, out, area, []

    def save(name, obj):
        with open(os.path.join(out, name), "w") as f:
            json.dump(redact(obj), f, indent=2)

    def fetch(path, name, keep=True):
        data, err = api.get(path)
        if err:
            c.errors.append("%s: %s" % (path, err))
            return None
        if keep:
            save(name, data)
        return data

    c.save, c.fetch = save, fetch
    cluster = fetch("/manage/v2?format=json", "cluster.json")
    c.version = str(first(cluster or {}, "version", default="unknown"))
    m = re.match(r"(\d+)", c.version)
    c.major = int(m.group(1)) if m else 0
    c.hosts = fetch("/manage/v2/hosts?view=status&format=json", "hosts-status.json")
    c.hostnames = list_names(c.hosts)
    c._trusted = None
    c._certs = None
    c.probed = set()
    say("# %s configuration gather" % {"saml": "SAML", "oauth": "OAuth", "ldap": "LDAP", "https": "HTTPS app server"}[area])
    say("")
    say("Collected %s UTC from %s:%s as `%s`. Nothing was changed on the server." % (NOW.strftime("%Y-%m-%d %H:%M"), a.host, a.port, a.user))
    say("")
    say("MarkLogic version: %s (cluster `%s`)" % (c.version, first(cluster or {}, "name", default="?")))
    if c.hostnames:
        say("Hosts: %s" % ", ".join(c.hostnames))
    say("")
    return c


def scalar_rows(props, limit=80):
    """Non-secret scalar settings of a Management API object, as table rows."""
    rows = []
    for k, v in walk(props):
        if isinstance(v, (dict, list)) or v in (None, ""):
            continue
        if SECRET_KEY_RE.search(k) or "BEGIN" in str(v) or len(str(v)) > 200:
            continue
        rows.append((k, str(v)))
        if len(rows) >= limit:
            break
    return rows


def say_table(rows, head=("Setting", "Value")):
    say("| %s | %s |" % head)
    say("|---|---|")
    for k, v in rows:
        say("| %s | `%s` |" % (k, v.replace("|", "\\|")))
    say("")


def scan_profiles(c, auth_type):
    """Read the external security profile(s) of one authentication type; returns {name: properties}."""
    a = c.a
    listing = c.fetch("/manage/v2/external-security?format=json", "external-security-list.json", keep=False)
    all_names = list_names(listing)
    if a.external_security and all_names and a.external_security not in all_names:
        sys.exit("ERROR: external security profile '%s' not found. Profiles on this cluster: %s\n"
                 "Run with --help for all options." % (a.external_security, ", ".join(all_names)))
    found = {}
    for n in ([a.external_security] if a.external_security else all_names):
        props = c.fetch("/manage/v2/external-security/%s/properties?format=json" % q(n), "", keep=False)
        if not props:
            continue
        auth = first(props, "authentication")
        if auth != auth_type and not a.external_security:
            continue
        c.save("external-security-%s.json" % slug(n), props)
        if auth != auth_type:
            check("WARN", "%s is a `%s` profile" % (n, auth), "this area expects `%s`; settings are shown but the %s checks may not apply" % (auth_type, auth_type))
        found[n] = props
    if not found:
        say("No %s external security profile found%s." % (auth_type, " (or it could not be read; see errors below)" if a.external_security else ""))
        say("")
        missing("External security profile", "none of type `%s` found" % auth_type,
                "check the profile name (Admin Interface > Security > External Security) and pass --external-security <name>")
    return found


def bound_servers(c, names):
    """App servers that use any of the named external security profiles."""
    servers = c.fetch("/manage/v2/servers?format=json", "servers-list.json", keep=False)
    items = []
    for k, v in walk(servers or {}):
        if k == "list-item":
            items.extend(v if isinstance(v, list) else [v])
    out = []
    say("## App servers using these profiles")
    say("")
    for it in items:
        if not isinstance(it, dict) or "nameref" not in it:
            continue
        nm, grp = it["nameref"], it.get("groupnameref", "Default")
        sp = c.fetch("/manage/v2/servers/%s/properties?group-id=%s&format=json" % (q(nm), q(grp)), "", keep=False)
        if not sp:
            continue
        used = [str(x) for x in find_all(sp, "external-security")]
        if not any(u in names for u in used):
            continue
        c.save("server-%s-%s.json" % (grp, slug(nm)), sp)
        out.append({"name": nm, "group": grp, "port": first(sp, "port"), "props": sp})
        say("- `%s` (group `%s`, port %s): authentication `%s`, external-security `%s`, TLS template `%s`" % (
            nm, grp, first(sp, "port"), first(sp, "authentication"), ", ".join(used), first(sp, "ssl-certificate-template", default="none")))
    if not out:
        say("None found (the profile may not be bound to an app server, or the server list could not be read).")
        check("WARN", "profile is bound to an app server", "no app server referenced it")
        missing("App servers using the profile", "no app server references it (it may be unused, or the server list could not be read)",
                "check the app server's authentication settings")
    say("")
    return out


def describe_users(c, role_map_note):
    """The --user-name section: external names, roles, role external names and privileges. Returns the external-name map."""
    a = c.a
    if not a.user_name:
        missing("User and role external names", "no --user-name given",
                "add --user-name <MarkLogic user the login maps to>")
        return None
    say("## Users, roles and external names")
    say("")
    allmap, role_cache, role_priv = {}, {}, {}

    def role_ext(role, depth=0):
        if role in role_cache or depth > 5:
            return
        rp = c.fetch("/manage/v2/roles/%s/properties?format=json" % q(role), "role-%s.json" % slug(role))
        role_cache[role] = ([str(x) for x in find_all(rp or {}, "external-name")], [str(x) for x in find_all(rp or {}, "role")])
        role_priv[role] = [str(x).rsplit("/", 1)[-1] for k, x in walk(rp or {}) if k == "action"]
        for en in role_cache[role][0]:
            allmap.setdefault(en, []).append("role " + role)
        for r in role_cache[role][1]:
            role_ext(r, depth + 1)

    for un in a.user_name:
        up = c.fetch("/manage/v2/users/%s/properties?format=json" % q(un), "user-%s.json" % slug(un))
        if not up:
            say("- `%s`: could not be read (see errors)" % un)
            check("FAIL", "user %s exists" % un, "could not read user properties")
            continue
        ens = [str(x) for x in find_all(up, "external-name")]
        roles = [str(x) for x in find_all(up, "role")]
        for en in ens:
            allmap.setdefault(en, []).append("user " + un)
        for r in roles:
            role_ext(r)
        say("- `%s`: external names %s; roles %s" % (un, ens or "none", roles or "none"))
        for r in roles:
            if r in role_cache:
                say("  - role `%s` external names: %s; inherits %s; privileges: %s" % (
                    r, role_cache[r][0] or "none", role_cache[r][1] or "none", ", ".join(role_priv.get(r, [])[:25]) or "none"))
    say("")
    say(role_map_note)
    say("")
    return {"all": allmap}


# ---------------------------------------------------------------- certificates in the Security database
DN_LABELS = [("countryName", "C"), ("stateOrProvinceName", "ST"), ("localityName", "L"), ("organizationName", "O"),
             ("organizationalUnitName", "OU"), ("commonName", "CN")]


def dn_text(d):
    d = d or {}
    parts = ["%s=%s" % (lab, d[k]) for k, lab in DN_LABELS if k in d]
    parts += ["%s=%s" % (k, v) for k, v in d.items() if k not in dict(DN_LABELS)]
    return ", ".join(parts)


def norm_serial(x):
    return str(x or "").lstrip("0").upper()


def security_certs(c):
    """Every certificate in the Security database: trusted authorities (also the temporary ones MarkLogic generates for a
    template) and host certificates. Read through the Management API (no PEM is returned, only the parsed fields)."""
    if getattr(c, "_certs", None) is not None:
        return c._certs
    jobs = []
    for res, kind in (("certificate-authorities", "authority"), ("certificates", "host")):
        data = c.fetch("/manage/v2/%s?format=json" % res, "", keep=False)
        for k, v in walk(data or {}):
            if k == "list-item":
                for it in (v if isinstance(v, list) else [v]):
                    if isinstance(it, dict) and "idref" in it:
                        jobs.append((res, kind, it["idref"], it.get("nameref")))

    def one(job):
        res, kind, i, listed_as = job
        d, err = c.api.get("/manage/v2/%s/%s?format=json" % (res, q(i)))
        if err or not d:
            return None
        d = d[list(d)[0]]
        cert = d.get("cert") or {}
        v3 = cert.get("v3ext") or {}
        val = cert.get("validity") or {}
        return {"id": str(d.get("id", i)), "kind": kind, "label": str(listed_as if listed_as is not None else d.get("host-name", "")), "temporary": str(d.get("temporary")).lower() == "true",
                "template_id": str(d["template-id"]) if d.get("template-id") not in (None, "") else None,
                "template_version": d.get("template-version"), "authority": str(d.get("authority")).lower() == "true",
                "enabled": d.get("enabled"), "subject": cert.get("subject") or {}, "issuer": cert.get("issuer") or {},
                "serial": norm_serial(cert.get("serialNumber")), "ski": str((v3.get("subjectKeyIdentifier") or {}).get("value", "")).upper(),
                "aki": str((v3.get("authorityKeyIdentifier") or {}).get("value", "")).upper(),
                "not_before": str(val.get("notBefore", "")), "not_after": str(val.get("notAfter", "")), "sigalg": cert.get("signatureType"),
                "san": str((v3.get("subjectAltName") or {}).get("value", ""))}

    with concurrent.futures.ThreadPoolExecutor(max_workers=12) as pool:
        c._certs = [x for x in pool.map(one, jobs) if x]
    return c._certs


def cert_expiry_text(not_after):
    d = parse_iso(not_after) if not_after else None
    if not d:
        return not_after or "?"
    left = (d - NOW).days
    return "%s (%s)" % (not_after[:10], "EXPIRED" if left < 0 else "%d days" % left)


def templates_by_id(c):
    data = c.fetch("/manage/v2/certificate-templates?format=json", "", keep=False)
    out = {}
    for k, v in walk(data or {}):
        if k == "list-item":
            for it in (v if isinstance(v, list) else [v]):
                if isinstance(it, dict) and "idref" in it:
                    td = c.fetch("/manage/v2/certificate-templates/%s?format=json" % q(it["idref"]), "", keep=False)
                    if td:
                        out[str(it["idref"])] = {"name": it.get("nameref"), "version": first(td, "template-version"),
                                                 "gen_temp": str(first(td, "generate-temp-certificate")).lower() == "true",
                                                 "key_type": first(td, "key-type")}
    return out


def template_report(c, tid, tname):
    """Say, for one template, whether its certificate is TEMPORARY (made by MarkLogic) or PERMANENT (issued by a CA)."""
    certs = [x for x in security_certs(c) if x["template_id"] == str(tid)]
    done = c.__dict__.setdefault("_tpl_done", set())
    if str(tid) in done:
        say("Template `%s`: status as reported above." % tname)
        say("")
        return certs
    done.add(str(tid))
    tinfo = templates_by_id(c).get(str(tid), {}) if tid else {}
    say("#### Certificate status of template `%s`" % tname)
    say("")
    if not certs:
        say("No certificate is stored for this template.")
        say("")
        check("FAIL" if not tinfo.get("gen_temp") else "WARN", "%s: certificate present" % tname,
              "the template holds no certificate and temporary certificate generation is %s: an app server using it cannot serve TLS properly" % ("off" if not tinfo.get("gen_temp") else "on but none exists"))
        return []
    say("| Certificate | Status | Subject | Issued by | Valid until | Serial | Template version |")
    say("|---|---|---|---|---|---|---|")
    for x in sorted(certs, key=lambda x: (not x["temporary"], x["not_after"])):
        self_signed = dn_text(x["subject"]) == dn_text(x["issuer"])
        status = "**TEMPORARY** (generated by MarkLogic, self-signed)" if x["temporary"] else (
            "**PERMANENT**, self-signed" if self_signed else "**PERMANENT**, signed by a certificate authority")
        say("| %s | %s | `%s` | `%s` | %s | `%s` | %s |" % (x["id"], status, dn_text(x["subject"]), dn_text(x["issuer"]),
                                                          cert_expiry_text(x["not_after"]), x["serial"], x["template_version"]))
        d = parse_iso(x["not_after"]) if x["not_after"] else None
        if d and (d - NOW).days < 0:
            check("FAIL", "%s: certificate %s expired" % (tname, x["id"]), "expired %s" % x["not_after"][:10])
        elif d and (d - NOW).days < 30:
            check("WARN", "%s: certificate %s expires soon" % (tname, x["id"]), "%d days left" % (d - NOW).days)
        if x["template_version"] not in (None, "") and tinfo.get("version") not in (None, "") and str(x["template_version"]) != str(tinfo["version"]):
            check("INFO", "%s: certificate %s was issued for template version %s" % (tname, x["id"], x["template_version"]),
                  "the template is now version %s; the certificate may not reflect the template's current subject or key settings" % tinfo["version"])
    say("")
    perm = [x for x in certs if not x["temporary"]]
    temp = [x for x in certs if x["temporary"]]
    if perm:
        non_self = [x for x in perm if dn_text(x["subject"]) != dn_text(x["issuer"])]
        check("PASS" if non_self else "INFO", "%s: permanent certificate" % tname,
              ("issued by %s" % ", ".join(sorted({x["issuer"].get("commonName", "?") for x in non_self}))) if non_self else "permanent but self-signed")
        if temp:
            check("INFO", "%s: a temporary certificate is also present" % tname, "the permanent certificate is the one to serve; compare with the certificate the port serves")
    else:
        check("WARN", "%s: certificate is TEMPORARY" % tname,
              "only a temporary certificate generated by MarkLogic exists. It is self-signed, so clients do not trust it and its name rarely matches the host. "
              "Generate a certificate request on the template, have it signed by a certificate authority and import the signed certificate")
    return certs


def duplicates_report(c):
    """Certificates in the Security database that share a subject, classified, and labels that differ from the subject."""
    certs = security_certs(c)
    groups = {}
    for x in certs:
        groups.setdefault(dn_text(x["subject"]), []).append(x)
    dups = {k: v for k, v in groups.items() if len(v) > 1}
    say("### Certificates with the same subject in the Security database")
    say("")
    if not dups:
        say("None: every certificate has its own subject.")
        say("")
    else:
        say("MarkLogic logs `Duplicate certificate subject found in Security Database` (as a Warning) for these. Two certificates may legitimately share a subject, "
            "but the Admin Interface lists then look the same, so the table says what each pair is.")
        say("")
        say("| Subject | Kind | Serial | Valid until | Key identifier | Issued by | Used by template |")
        say("|---|---|---|---|---|---|---|")
        tpl = templates_by_id(c)
        for sub, members in sorted(dups.items()):
            for x in members:
                say("| `%s` | %s | `%s` | %s | `%s` | `%s` | %s |" % (
                    sub, "host certificate" if x["kind"] == "host" else ("temporary CA" if x["temporary"] else "CA"), x["serial"][:16],
                    cert_expiry_text(x["not_after"]), x["ski"][:17] or "none", x["issuer"].get("commonName") or dn_text(x["issuer"]) or "?",
                    (tpl.get(x["template_id"], {}).get("name") or x["template_id"]) if x["template_id"] else "-"))
            kinds = {m["kind"] for m in members}
            skis = {m["ski"] for m in members}
            if kinds == {"host"}:
                tn = sorted({(tpl.get(m["template_id"], {}).get("name") or "?") for m in members})
                check("INFO", "duplicate subject `%s` (host certificates)" % sub,
                      "%d host certificates for the same name, held by the templates %s (for example an RSA and an EC template for one host). Harmless, but make sure each app server uses the intended template" % (len(members), ", ".join(tn)))
            elif "" in skis and len(skis) == 1:
                check("INFO", "duplicate subject `%s` (certificate authorities)" % sub,
                      "%d certificates without a key identifier (old certificates; this pattern is also present on a default MarkLogic installation) - the keys cannot be compared" % len(members))
            elif len(skis - {""}) == 1:
                check("INFO", "duplicate subject `%s` (certificate authorities)" % sub,
                      "same key, different certificates (for example a self-signed root and its cross-signed copy, or a re-issued CA certificate): both are trusted; harmless")
            else:
                check("WARN", "duplicate subject `%s` (certificate authorities)" % sub,
                      "%d different CA keys share one subject: a chain can only be verified against the right one (the key identifier decides), and the Admin Interface lists show identical names. Remove the one that is not needed" % len(members))
        say("")
    labels = []
    for x in certs:
        cn = x["subject"].get("commonName", "")
        if x["kind"] == "authority" and x["label"] and cn and x["label"] != cn and not x["temporary"]:
            labels.append(x)
    if labels:
        say("### Certificate authority list names that differ from the certificate's subject")
        say("")
        say("| Name in the Admin Interface / Management API list | Real subject | Issued by |")
        say("|---|---|---|")
        for x in labels:
            say("| `%s` | `%s` | `%s` |" % (x["label"], x["subject"].get("commonName", ""), x["issuer"].get("commonName", "")))
        say("")
        check("INFO", "%d certificate authority list name(s) differ from the subject" % len(labels),
              "an imported intermediate can be listed under the name of its root, so two list entries look the same; use the serial number or subject to tell them apart")


# ---------------------------------------------------------------- TLS probing
def tls_probe(host, port, starttls=None, cafile=None, timeout=20):
    """Handshake with openssl s_client and return the chain presented, the negotiated protocol and cipher."""
    cmd = ["openssl", "s_client", "-connect", "%s:%s" % (host, port), "-showcerts"]
    if not re.match(r"^[\d.]+$|:", host):
        cmd += ["-servername", host]
    if starttls:
        cmd += ["-starttls", starttls]
    if cafile:
        cmd += ["-CAfile", cafile]
    try:
        r = subprocess.run(cmd, input="", capture_output=True, text=True, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired) as e:
        return {"error": "openssl s_client: %s" % e}
    txt = r.stdout + r.stderr
    res = {"raw_ok": "BEGIN CERTIFICATE" in txt}
    res["certs"] = [base64.b64decode(re.sub(r"\s+", "", b)) for b in PEM_RE.findall(txt)]
    m = re.search(r"Verify return code: (\d+) \((.*?)\)", txt)
    res["verify_code"], res["verify_msg"] = (int(m.group(1)), m.group(2)) if m else (None, "")
    m = re.search(r"Protocol\s*:\s*(\S+)", txt) or re.search(r"New, (\S+), Cipher is (\S+)", txt)
    res["protocol"] = m.group(1) if m else None
    m = re.search(r"Cipher\s*:\s*(\S+)", txt) or re.search(r"Cipher is (\S+)", txt)
    res["cipher"] = m.group(1) if m else None
    if res["cipher"] in ("0000", "(NONE)"):
        res["cipher"], res["protocol"] = None, None
    res["client_cert_requested"] = ("Acceptable client certificate CA names" in txt) and "No client certificate CA names sent" not in txt
    if not res["certs"]:
        m = re.search(r"(connect:errno=\d+|Connection refused|getaddrinfo.*|timed out|errno=\d+)", txt)
        if m:
            res["error"] = m.group(1)
        elif re.search(r"shutdown while in init|handshake failure|no peer certificate|alert", txt, re.I):
            res["error"] = ("the TLS handshake failed before the server sent a certificate. Typical causes: the app server's certificate template "
                            "holds no certificate (ErrorLog: 'Failed to find server certificate in certificate template'), or the client and server share no protocol version or cipher")
        else:
            res["error"] = (txt.strip().splitlines() or ["no certificate returned"])[-1][:160]
    return res


def legacy_client_probe(host, port, timeout=20):
    """Can a TLS 1.2 client without the extended master secret extension (like MarkLogic 11's HTTPS client) connect?
    Returns True/False, or None when this openssl cannot run the test."""
    cmd = ["openssl", "s_client", "-connect", "%s:%s" % (host, port), "-tls1_2", "-no_ems"]
    if not re.match(r"^[\d.]+$|:", host):
        cmd += ["-servername", host]
    try:
        r = subprocess.run(cmd, input="", capture_output=True, text=True, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired):
        return None
    txt = r.stdout + r.stderr
    if re.search(r"unknown option|Invalid option|-no_ems", txt) and "BEGIN CERTIFICATE" not in txt:
        return None
    m = re.search(r"New, (\S+), Cipher is (\S+)", txt)
    return bool(m and m.group(2) not in ("(NONE)", "0000"))


def host_matches(der, host):
    rc, out = openssl(["x509", "-noout", "-checkhost", host], der_to_pem(der))
    if rc != 0 and "unknown option" in out.lower():
        return None
    return "does match" in out


def load_trusted_cas(c):
    """MarkLogic's trusted certificate authorities: (subject common name, subject key identifier, notAfter)."""
    if c._trusted is None:
        c._trusted = [(x["subject"].get("commonName", ""), x["ski"], x["not_after"]) for x in security_certs(c)
                      if x["kind"] == "authority" and not x["temporary"]]
    return c._trusted


def ml_trust_of_chain(c, ders):
    """Which certificate of a chain is in MarkLogic's trusted CA list (by key identifier or name)?"""
    cas = load_trusted_cas(c)
    for n, der in enumerate(ders):
        info = cert_info(der)
        for cn, ski, na in cas:
            if (info.get("ski") and info["ski"] == ski) or (cn and info.get("subject", "").endswith("CN=" + cn)):
                return cn
            # the last certificate sent is often issued by a root that is not sent: check its issuer too
            if n == len(ders) - 1 and ((info.get("aki") and info["aki"] == ski) or (cn and info.get("issuer", "").endswith("CN=" + cn))):
                return cn + " (the issuer of the last certificate sent)"
    return None


def analyse_tls_chain(c, label, probe, host, check_ml_trust=False):
    """Chain analysis, hostname check and trust results for the output of tls_probe."""
    if probe.get("error"):
        say("Could not read the certificate presented by %s: %s" % (label, probe["error"]))
        check("FAIL", "%s reachable" % label, probe["error"])
        return []
    ders = probe["certs"]
    infos = analyse_chain(label, "".join(der_to_pem(d) for d in ders),
                          issuer_note="Informational: a server normally does not send its root certificate. What matters is that the root is trusted by the side that verifies it (see the trust checks)")
    if infos and host:
        ok = host_matches(ders[0], host)
        if ok is not None:
            check("PASS" if ok else "FAIL", "%s certificate matches host name %s" % (label, host),
                  "" if ok else "the name is not in the certificate's subject alternative names or common name (%s)" % infos[0].get("subject", "?"))
    code = probe.get("verify_code")
    if code is not None:
        check("PASS" if code == 0 else "WARN", "%s trusted by this machine" % label,
              "verification result: %s (%s). This is this machine's trust store, not MarkLogic's" % (code, probe.get("verify_msg")))
    if check_ml_trust and ders:
        hit = ml_trust_of_chain(c, ders)
        if hit:
            check("PASS", "%s chain is trusted by MarkLogic" % label, "found in MarkLogic's certificate authorities: %s" % hit)
        else:
            check("WARN", "%s chain is trusted by MarkLogic" % label,
                  "no certificate of the chain is in MarkLogic's trusted certificate authorities (Admin Interface > Security > Certificate Authorities); "
                  "MarkLogic cannot verify this server's certificate unless the CA is added")
    if probe.get("protocol"):
        say("- Negotiated: %s, cipher %s" % (probe["protocol"], probe.get("cipher")))
        say("")
    return infos


# ---------------------------------------------------------------- generic logs (OAuth, LDAP, HTTPS)
OAUTH_HINTS = [
    (r"OAuth Error: 'invalid_request'", "The IdP refused the authorization request and sent the browser back with this error. In authentik the usual cause is that the provider does not allow the `authorization_code` grant type (the IdP's own log says `Invalid grant_type for provider`)."),
    (r"OAuth Error: 'invalid_client'|invalid_client", "The IdP does not accept the client id / client secret / authentication method that MarkLogic sent to the token endpoint."),
    (r"OAuth Error: 'invalid_grant'|invalid_grant", "The IdP rejected the authorization code (already used, expired after about a minute, or the redirect URI sent to the token endpoint differs from the one used to authorize)."),
    (r"OAuth Error", "The IdP returned an OAuth error to MarkLogic; the error code and description are in the message."),
    (r"SVC-SOCCONN|Socket connect|SSL_connect", "MarkLogic could not open a TLS connection to the IdP (JWKS or token endpoint): network, CA trust, or a TLS protocol/extension the IdP requires (see the IdP endpoint checks)."),
    (r"Issuer URI must be configured", "`oauth-jwt-issuer-uri` is not set; MarkLogic validates the token's `iss` claim against it."),
    (r"JWT validation failed, re-initiating", "Token validation failed and MarkLogic restarted the authorization flow (the browser loops back to the IdP). The line before it gives the reason."),
    (r"Access token provided is empty", "The request carries no bearer token, or an empty one."),
    (r"signature", "The token signature does not verify with the key MarkLogic holds. Look for rotated IdP keys; compare `kid` and the JWKS (the `--token` check does this)."),
    (r"[Ii]ssuer|\biss\b", "The token `iss` must equal `oauth-jwt-issuer-uri` exactly, including any trailing slash."),
    (r"expired|\bexp\b|not before|\bnbf\b", "Validity window problem: token lifetime, or clock difference between the IdP and the MarkLogic hosts."),
    (r"jwks|JWKS", "The JWKS could not be fetched or holds no matching key: check `oauth-jwks-uri`, the network, and that MarkLogic trusts the IdP's TLS certificate authority."),
    (r"XDMP-OAUTH", "MarkLogic rejected the token or the OAuth flow; the message text says why."),
]
LDAP_HINTS = [
    (r"fail because authentication failure", "MarkLogic did not get a valid bind: wrong password or default user DN, or a bind method that does not support password login."),
    (r"fail because no LDAP user", "The bind worked but the search found no entry: check `ldap-base` and `ldap-attribute` with the exact user name."),
    (r"certificateAuthenticate\(\) fail because no user", "Certificate authentication found no MarkLogic user whose external name equals the DN shown."),
    (r"no external security is configured", "The app server needs an external security profile and none is selected."),
    (r"[Cc]an't contact LDAP|Connect.*fail|Unable to connect|timed out", "MarkLogic cannot reach the directory: network, port, or TLS."),
]
HTTPS_HINTS = [
    (r"Failed to find server certificate in certificate template", "The app server's certificate template holds no certificate (the number is the template id, resolved to a name in this report), so it cannot complete a TLS handshake. A template created through the Management API has no temporary certificate until one is generated or a signed certificate is imported."),
    (r"Duplicate certificate subject", "Two certificates in the Security database share a subject; see the table of duplicate subjects in this report. Usually harmless (an RSA and an EC template for one host name, cross-signed roots, MarkLogic's default CA bundle)."),
    (r"certificate verify failed|unknown ca|unable to get (local )?issuer", "A certificate chain could not be verified: the issuing CA is not trusted by the side that checked it."),
    (r"expired", "A certificate has expired."),
    (r"no shared cipher|handshake failure|wrong version number|protocol version", "Protocol or cipher mismatch between client and app server (check the app server's TLS settings)."),
]
LOG_AREAS = {
    "oauth": dict(events=("OAuth", "OAuth Status", "OAuth Communications", "OAuth JSON Processing", "External Authenticate"),
                  pattern=r"oauth|jwt|jwks", error=r"XDMP-OAUTH|OAuth Status.*(fail|error|invalid|must|empty)|JWT validation failed|[Ee]rror:|failed",
                  hints=OAUTH_HINTS, trace_event="OAuth", preset="oauth"),
    "ldap": dict(events=("External Authenticate", "LDAP", "LDAP Search"), pattern=r"ldap",
                 error=r"fail because|authentication failed|[Ee]rror:|failed|externalAuthenticate failed", hints=LDAP_HINTS,
                 trace_event="External Authenticate", preset="ldap"),
    "https": dict(events=(), pattern=r"ssl|tls|certificate|handshake", error=r"[Ee]rror|fail|Failed|invalid|expired|unable|SVC-|Duplicate certificate subject",
                  hints=HTTPS_HINTS, trace_event=None, preset=None),
}


def access_summary(c, ports, start, end):
    """Status codes per app server port from each host's AccessLog (not searchable by time: read whole, filter here)."""
    counts, bad, lines_out = {}, [], {}
    for h in c.hostnames:
        for port in sorted({p for p in ports if p}):
            text, err = c.api.get("/manage/v2/logs?filename=%s_AccessLog.txt&host=%s&format=text" % (q(port), q(h)), text=True)
            if err or text.lstrip().startswith("<error"):
                c.errors.append("%s_AccessLog.txt on %s: %s" % (port, h, err or text[:150].replace("\n", " ")))
                continue
            keep = []
            for raw in text.splitlines():
                t = TS_ACC.search(raw)
                if not t:
                    continue
                when = dt.datetime.strptime(t.group(1), "%d/%b/%Y:%H:%M:%S %z").astimezone(dt.timezone.utc)
                if start <= when <= end:
                    st = re.search(r'" (\d{3}) ', raw)
                    code = st.group(1) if st else "?"
                    counts[(port, code)] = counts.get((port, code), 0) + 1
                    clean = re.sub(r"\?\S*", "?<query removed>", scrub(raw))
                    keep.append(clean)
                    if code in ("401", "403") or code.startswith("5"):
                        bad.append((port, iso(when), clean[:240]))
            lines_out[(h, port)] = keep
    return counts, bad, lines_out


def analyse_logs_generic(c, area, bound):
    a = c.a
    cfgl = LOG_AREAS[area]
    start, end = window(a)
    say("## Logs (%s to %s UTC)" % (iso(start), iso(end)))
    say("")
    say("Log times are written in each host's local time zone; the window above is UTC. If a host is not on UTC, widen the window or pass --start/--end. The ErrorLog does not say which app server a line belongs to: if several app servers use external security at the same time, reproduce one login at a time (the AccessLog is per app server).")
    say("")
    if cfgl["trace_event"]:
        for grp in sorted({b["group"] for b in bound} or {"Default"}):
            gp = c.fetch("/manage/v2/groups/%s/properties?format=json" % q(grp), "", keep=False)
            if not gp:
                continue
            ev = [str(x) for x in find_all(gp, "event")]
            on = bool(first(gp, "events-activated", default=False))
            say("- Trace events, group `%s`: mechanism %s, events: %s" % (grp, "ON" if on else "off", ", ".join(ev) or "none"))
            if not (on and cfgl["trace_event"] in ev):
                check("WARN", "%s trace events enabled on group %s" % (area.upper(), grp),
                      "off: the ErrorLog will not show why a login is rejected. Run ml-trace-events.py enable --preset %s, reproduce, then gather again" % cfgl["preset"])
        say("")
    all_msgs = []
    for h in c.hostnames:
        text, err = c.api.get("/manage/v2/logs?filename=ErrorLog.txt&host=%s&format=text&start=%s&end=%s" % (q(h), q(iso(start)), q(iso(end))), text=True)
        if err or text.lstrip().startswith("<error"):
            c.errors.append("ErrorLog on %s: %s" % (h, err or text[:200].replace("\n", " ")))
            continue
        kept = keep_error_lines(text, cfgl["events"], cfgl["pattern"])
        with open(os.path.join(c.out, "ErrorLog-%s-%s.txt" % (area, slug(h))), "w") as f:
            f.write("# ErrorLog lines about %s from %s, %s to %s UTC; long values removed\n" % (area, h, iso(start), iso(end)))
            for ts, level, msg in kept:
                f.write("%s %s: %s\n" % (ts, level, scrub(msg)))
        say("- ErrorLog on `%s`: %d relevant line(s) in the window (saved as ErrorLog-%s-*.txt)" % (h, len(kept), area))
        for ts, level, msg in kept:
            all_msgs.append((h, ts, level, msg))
    say("")
    if not all_msgs:
        say("No relevant lines in the window.")
        check("WARN", "%s lines found in the ErrorLog window" % area.upper(), "none: trace events off, no attempt in the window, or a time-zone offset")
    else:
        say("### Messages seen")
        say("")
        norm = {}
        for h, ts, level, body in all_msgs:
            k = re.sub(r"\d{4}-\d{2}-\d{2}T[\d:]+Z", "<time>", scrub(body))[:120]
            norm[k] = norm.get(k, 0) + 1
        say("| Count | Message |")
        say("|---|---|")
        for k, v in sorted(norm.items(), key=lambda kv: -kv[1])[:40]:
            say("| %d | %s |" % (v, k.replace("|", "\\|")))
        say("")
        if area == "https":
            tn = {k: v.get("name") for k, v in templates_by_id(c).items()}
            all_msgs = [(h, ts, level, re.sub(r"certificate template (\d+)", lambda m: "certificate template %s (%s)" % (m.group(1), tn.get(m.group(1), "unknown")), b))
                        for h, ts, level, b in all_msgs]
        benign = r"External authentication failed: user=\s*$|stateVal: \(empty\)"
        errs = [(ts, scrub(b)[:160], level) for h, ts, level, b in all_msgs
                if re.search(cfgl["error"], b) and not re.search(r"\bpass\b", b) and not re.search(benign, scrub(b))]
        grouped, levels = {}, {}
        for ts, b, level in errs:
            grouped.setdefault(b, []).append(ts)
            levels[b] = level
        for msg, times in list(grouped.items())[:15]:
            hint = next((t for pat, t in cfgl["hints"] if re.search(pat, msg)), None)
            check("WARN" if levels[msg] == "Warning" else "FAIL", "%s %s, first at %s (%d time%s)" % (area.upper(), "warning" if levels[msg] == "Warning" else "error", times[0], len(times), "" if len(times) == 1 else "s"),
                  "`%s`%s" % (msg, (" - " + hint) if hint else ""))
        if area == "oauth":
            redirects = sum(1 for _, _, _, b in all_msgs if re.search(r"OAuth redirect URI: https?://\S*(authorize|auth)", b))
            callbacks = sum(1 for _, _, _, b in all_msgs if "via the 'authorization_code' flow" in b or "OAuth Error" in b)
            if redirects and not callbacks:
                check("WARN", "browser was sent to the IdP but never came back",
                      "%d redirect(s) to the IdP and no return with an authorization code in the window. Check what the browser showed at the IdP "
                      "(for example a redirect URI error) and the IdP's own log: the redirect URI registered at the IdP must equal `oauth-redirect-uri` "
                      "(MarkLogic sends the app server URL), and the provider must allow the authorization_code grant" % redirects)
        passes = sum(1 for _, _, _, b in all_msgs if re.search(r"\bpass\b", b))
        if passes and not errs:
            check("PASS", "external authentication passed", "%d pass line(s); no error lines" % passes)
        if any("External authentication failed: user=" in b for _, _, _, b in all_msgs):
            say("(`External authentication failed: user=` lines with no user name appear for the first request, before a session exists; they are normal.)")
            say("")
    ports = [b["port"] for b in bound]
    if ports:
        counts, bad, lines_out = access_summary(c, ports, start, end)
        for (h, port), keep in lines_out.items():
            with open(os.path.join(c.out, "AccessLog-%s-%s.txt" % (port, slug(h))), "w") as f:
                f.write("# %s_AccessLog.txt from %s, %s to %s UTC (query strings removed)\n" % (port, h, iso(start), iso(end)))
                f.write("\n".join(keep[-300:]) + "\n")
        if counts:
            say("### HTTP status codes in the window (app server AccessLog)")
            say("")
            for (port, code), v in sorted(counts.items()):
                say("- port %s: %s x %d" % (port, code, v))
            say("")
            for port, when, line in bad[-8:]:
                say("  - `%s`" % line)
            n401 = sum(1 for b in bad if '" 401 ' in b[2])
            n403 = sum(1 for b in bad if '" 403 ' in b[2])
            if n401:
                check("INFO", "401 responses in the window", "%d: authentication was refused; see the error lines in the ErrorLog" % n401)
            if n403:
                check("INFO", "403 responses in the window", "%d: the user authenticated but lacks a role or privilege for the URL (authorization failures are in the AccessLog, not the ErrorLog)" % n403)
            say("")


def tls_lines_note():
    say("(The TLS checks run from this machine, which may differ from the MarkLogic hosts' view of the network and trust store.)")
    say("")


# ---------------------------------------------------------------- OAuth
def b64url(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def curl_json(url, insecure=False, timeout=25):
    cmd = ["curl", "-sSL", "--max-time", str(timeout), "-w", "\n%{http_code}"]
    if insecure:
        cmd.append("-k")
    r = subprocess.run(cmd + [url], capture_output=True, text=True)
    if r.returncode != 0:
        return None, "curl error %d: %s" % (r.returncode, r.stderr.strip()[:140]), r.returncode
    body, _, code = r.stdout.rpartition("\n")
    if code != "200":
        return None, "HTTP %s" % code, 0
    try:
        return json.loads(body), None, 0
    except ValueError:
        return None, "not JSON", 0


def get_json_probe(url):
    """Fetch a JSON document; if only the TLS trust fails, retry without verification and say so."""
    d, err, rc = curl_json(url)
    if d is None and rc in (35, 51, 58, 60, 77):
        d, err2, _ = curl_json(url, insecure=True)
        if d is not None:
            return d, "the IdP's TLS certificate is not trusted by this machine (document read without verification)"
    return d, err


def der_len(n):
    return bytes([n]) if n < 128 else bytes([0x80 | len(n.to_bytes((n.bit_length() + 7) // 8, "big"))]) + n.to_bytes((n.bit_length() + 7) // 8, "big")


def der(tag, body):
    return bytes([tag]) + der_len(len(body)) + body


def der_int(b):
    b = b.lstrip(b"\x00") or b"\x00"
    if b[0] & 0x80:
        b = b"\x00" + b
    return der(0x02, b)


def rsa_jwk_to_pem(jwk):
    n, e = b64url(jwk["n"]), b64url(jwk["e"])
    rsapub = der(0x30, der_int(n) + der_int(e))
    algid = der(0x30, bytes.fromhex("06092a864886f70d010101") + b"\x05\x00")
    spki = der(0x30, algid + der(0x03, b"\x00" + rsapub))
    b = base64.b64encode(spki).decode()
    return "-----BEGIN PUBLIC KEY-----\n" + "\n".join(b[i:i + 64] for i in range(0, len(b), 64)) + "\n-----END PUBLIC KEY-----\n"


def verify_rs256(jwk, signing_input, sig):
    with tempfile.TemporaryDirectory() as d:
        pk, sg, dt_ = os.path.join(d, "k.pem"), os.path.join(d, "s.bin"), os.path.join(d, "d.bin")
        open(pk, "w").write(rsa_jwk_to_pem(jwk))
        open(sg, "wb").write(sig)
        open(dt_, "wb").write(signing_input)
        r = subprocess.run(["openssl", "dgst", "-sha256", "-verify", pk, "-signature", sg, dt_], capture_output=True, text=True)
    return r.returncode == 0 and "Verified OK" in r.stdout


def analyse_token(path, cfg, jwks, role_map, ext_names):
    say("## Token check")
    say("")
    raw = open(path, encoding="utf-8", errors="replace").read().strip()
    m = re.search(r"[Bb]earer\s+([A-Za-z0-9._~+/=-]+)", raw)
    tok = m.group(1) if m else re.search(r"[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*", raw)
    tok = tok if isinstance(tok, str) else (tok.group(0) if tok else None)
    if not tok or tok.count(".") != 2:
        say("The file does not contain a JWT (three dot-separated parts), or it is encrypted (JWE).")
        check("FAIL", "token readable", "not a JWT")
        missing("Token comparison", "the file is not a readable JWT", "give a file with the access token, or the Authorization header line")
        return
    h64, p64, s64 = tok.split(".")
    try:
        header, claims = json.loads(b64url(h64)), json.loads(b64url(p64))
    except ValueError:
        say("The token header or payload is not valid JSON.")
        check("FAIL", "token readable", "header or payload not JSON")
        return
    alg, kid = header.get("alg"), header.get("kid")
    say("- Header: alg `%s`, kid `%s`, typ `%s`" % (alg, kid, header.get("typ")))
    say("- Claim names: %s" % ", ".join("`%s`" % k for k in claims))
    iss, aud = claims.get("iss"), claims.get("aud")
    say("- iss: `%s`; aud: `%s`; azp: `%s`" % (iss, aud, claims.get("azp")))
    for k in ("iat", "nbf", "exp"):
        if isinstance(claims.get(k), (int, float)):
            say("- %s: %s UTC" % (k, dt.datetime.fromtimestamp(claims[k], dt.timezone.utc).strftime("%Y-%m-%d %H:%M:%S")))
    if isinstance(claims.get("exp"), (int, float)):
        say("  (a captured token is normally expired by now; compare with the time of the failed request, not with the time of this check)")
    ci = cfg.get("oauth-jwt-issuer-uri")
    if ci:
        check("PASS" if iss == ci else "FAIL", "token iss = oauth-jwt-issuer-uri", "config `%s` / token `%s`" % (ci, iss))
    if cfg.get("oauth-jwt-alg"):
        check("PASS" if alg == cfg["oauth-jwt-alg"] else "FAIL", "token alg = oauth-jwt-alg", "config `%s` / token `%s`" % (cfg["oauth-jwt-alg"], alg))
    cid = cfg.get("oauth-client-id")
    if cid and (aud is not None or claims.get("azp")):
        auds = aud if isinstance(aud, list) else [aud]
        check("PASS" if (cid in auds or claims.get("azp") == cid) else "WARN", "token audience / authorized party contains the client id",
              "client id `%s` / aud `%s` / azp `%s`" % (cid, aud, claims.get("azp")))
    ua = cfg.get("oauth-username-attribute")
    if ua:
        check("PASS" if ua in claims else "FAIL", "token has the username claim `%s`" % ua, "claim names: %s" % ", ".join(claims))
    ra = cfg.get("oauth-role-attribute")
    if ra:
        vals = claims.get(ra)
        vals = [] if vals is None else ([vals] if not isinstance(vals, list) else vals)
        if not vals:
            check("WARN", "token has role claim values in `%s`" % ra, "claim missing or empty")
        elif role_map is not None:
            hit = {str(v): role_map[str(v)] for v in vals if str(v) in role_map}
            if hit:
                check("PASS", "role claim values map to MarkLogic roles", "; ".join("`%s` -> %s" % (k, ", ".join(v)) for k, v in hit.items()))
            else:
                other = []
                for cn, cv in claims.items():
                    if cn == ra:
                        continue
                    cv = cv if isinstance(cv, list) else [cv]
                    m = [str(v) for v in cv if isinstance(v, (str, int)) and str(v) in role_map]
                    if m:
                        other.append("`%s` (%s)" % (cn, ", ".join(m)))
                check("FAIL", "role claim values map to a MarkLogic role",
                      "none of the %d value(s) in `%s` equals the external name of any role%s" % (len(vals), ra,
                      ". Another claim does match: %s. If that is the claim that carries the roles, set `oauth-role-attribute` to it" % "; ".join(other) if other else ""))
    if alg == "RS256" and jwks:
        keys = [k for k in jwks.get("keys", []) if k.get("kty") == "RSA"]
        cand = [k for k in keys if k.get("kid") == kid] or ([] if kid else keys)
        if not cand:
            check("FAIL", "token kid is in the JWKS", "kid `%s`; the JWKS holds: %s" % (kid, ", ".join(str(k.get("kid")) for k in jwks.get("keys", [])) or "no keys"))
        else:
            try:
                ok = verify_rs256(cand[0], (h64 + "." + p64).encode(), b64url(s64))
            except Exception as e:  # noqa: BLE001
                ok = None
                say("Signature check could not run: %s" % e)
            if ok is not None:
                check("PASS" if ok else "FAIL", "token signature verifies with the JWKS key", "kid `%s`" % cand[0].get("kid"))
    elif alg and alg != "RS256":
        missing("Token signature check", "only RS256 is checked (token alg is `%s`)" % alg, "n/a")
    elif not jwks:
        missing("Token signature check", "no JWKS was available", "allow the IdP's JWKS URL to be read from this machine")
    say("")


def run_oauth(c):
    a = c.a
    say("## OAuth external security profiles")
    say("")
    profiles = scan_profiles(c, "oauth")
    cfgs = {}
    for n, props in profiles.items():
        cfg = {k: first(props, k) for k in ("oauth-flow-type", "oauth-vendor", "oauth-client-id", "oauth-jwt-issuer-uri", "oauth-jwks-uri",
                                           "oauth-authorization-server-uri", "oauth-token-server-uri", "oauth-redirect-uri", "oauth-jwt-alg",
                                           "oauth-username-attribute", "oauth-role-attribute", "oauth-privilege-attribute", "authorization")}
        cfgs[n] = cfg
        flow = cfg["oauth-flow-type"]
        say("### `%s`" % n)
        say("")
        say_table(scalar_rows(props))
        say("The client secret is never read out of the Management API output here; it is removed before saving.")
        say("")
        # version rules
        if c.major and c.major < 12 and flow and "authorization" in str(flow).lower():
            check("FAIL", "%s: flow supported on MarkLogic %s" % (n, c.version),
                  "the Authorization code flow needs MarkLogic 12; MarkLogic 11 supports the Resource server flow only")
        if not flow:
            check("FAIL", "%s: oauth-flow-type is set" % n, "empty")
        is_ac = flow and "authorization" in str(flow).lower()
        need = ["oauth-client-id", "oauth-jwt-issuer-uri", "oauth-jwt-alg"] + (["oauth-authorization-server-uri", "oauth-token-server-uri", "oauth-redirect-uri"] if is_ac else [])
        for k in need:
            if not cfg.get(k):
                check("FAIL", "%s: %s is set" % (n, k), "empty")
        if not is_ac and not cfg.get("oauth-jwks-uri") and not first(props, "oauth-jwt-secret", default=None):
            check("WARN", "%s: signing keys configured" % n, "neither oauth-jwks-uri nor stored JWT secrets: MarkLogic has no key to verify tokens with")
        if is_ac:
            say("Authorization code flow: the client secret and redirect URI must match the client registered at the IdP (not readable from here).")
            say("")
        if not cfg.get("oauth-username-attribute"):
            check("WARN", "%s: oauth-username-attribute is set" % n, "empty")
    bound = bound_servers(c, set(profiles)) if profiles else []
    role_map = None
    if profiles and any(str(cfg.get("authorization")) == "oauth" for cfg in cfgs.values()):
        role_map = load_role_map(c.api, c.out, c.errors)
    ext = describe_users(c, "With authorization `oauth`, the values of the role claim are matched to the external names of roles.")
    # endpoint probes
    jwks_doc = None
    if profiles and not getattr(a, "no_probe", False):
        say("## IdP endpoints (read from this machine)")
        say("")
        tls_lines_note()
        for n, cfg in cfgs.items():
            iss = cfg.get("oauth-jwt-issuer-uri")
            disc, note = (None, None)
            if iss:
                url = iss.rstrip("/") + "/.well-known/openid-configuration"
                disc, note = get_json_probe(url)
                c.probed.add(url)
                if disc is None:
                    say("- Discovery document `%s`: not readable (%s)" % (url, note))
                    check("WARN", "%s: discovery document readable" % n, "%s: %s" % (url, note))
                else:
                    say("- Discovery document `%s`: read%s" % (url, " (%s)" % note if note else ""))
                    check("PASS" if disc.get("issuer") == iss else "FAIL", "%s: discovery issuer = oauth-jwt-issuer-uri" % n,
                          "config `%s` / discovery `%s`" % (iss, disc.get("issuer")))
                    for ck, dk in (("oauth-authorization-server-uri", "authorization_endpoint"), ("oauth-token-server-uri", "token_endpoint"),
                                   ("oauth-jwks-uri", "jwks_uri")):
                        if cfg.get(ck) and disc.get(dk):
                            check("PASS" if cfg[ck] == disc[dk] else "WARN", "%s: %s = discovery %s" % (n, ck, dk),
                                  "config `%s` / discovery `%s`" % (cfg[ck], disc[dk]))
                    algs = disc.get("id_token_signing_alg_values_supported") or []
                    if algs and cfg.get("oauth-jwt-alg") and cfg["oauth-jwt-alg"] not in algs:
                        check("WARN", "%s: oauth-jwt-alg offered by the IdP" % n, "config `%s` / IdP offers %s" % (cfg["oauth-jwt-alg"], ", ".join(algs)))
            ju = cfg.get("oauth-jwks-uri") or (disc or {}).get("jwks_uri")
            if ju:
                jd, jnote = get_json_probe(ju)
                if jd is None:
                    say("- JWKS `%s`: not readable (%s)" % (ju, jnote))
                    check("FAIL", "%s: JWKS readable" % n, "%s: %s" % (ju, jnote))
                else:
                    jwks_doc = jd
                    say("- JWKS `%s`: %d key(s)%s" % (ju, len(jd.get("keys", [])), " (%s)" % jnote if jnote else ""))
                    for k in jd.get("keys", []):
                        exp = ""
                        x5c = k.get("x5c")
                        if x5c:
                            ci = cert_info(base64.b64decode(x5c[0]))
                            if ci.get("not_after"):
                                left = (ci["not_after"] - NOW).days
                                exp = ", certificate %s" % ("EXPIRED" if left < 0 else "expires in %d days" % left)
                                if left < 0:
                                    check("FAIL", "%s: JWKS key %s certificate" % (n, str(k.get("kid"))[:12]), "expired")
                        say("  - kid `%s`, kty `%s`, alg `%s`, use `%s`%s" % (k.get("kid"), k.get("kty"), k.get("alg"), k.get("use"), exp))
            else:
                missing("JWKS check of profile `%s`" % n, "no oauth-jwks-uri and no discovery document", "set oauth-jwks-uri, or allow the discovery document to be read")
            hosts = set()
            for u in (iss, cfg.get("oauth-authorization-server-uri"), cfg.get("oauth-token-server-uri"), ju):
                m = re.match(r"https://([^/:]+)(?::(\d+))?", u or "")
                if m:
                    hosts.add((m.group(1), m.group(2) or "443"))
            for h, port in sorted(hosts):
                if (h, port) in c.probed:
                    say("- TLS of %s:%s: same as reported above" % (h, port))
                    continue
                c.probed.add((h, port))
                pr = tls_probe(h, port)
                analyse_tls_chain(c, "IdP endpoint %s:%s" % (h, port), pr, h, check_ml_trust=True)
                if c.major and c.major < 12 and not pr.get("error") and legacy_client_probe(h, port) is False:
                    check("FAIL", "IdP endpoint %s:%s accepts MarkLogic %s's HTTPS client" % (h, port, c.version),
                          "a TLS 1.2 handshake without the extended master secret extension is refused (the IdP needs TLS 1.3 or that extension, "
                          "for example a Go server in FIPS mode). MarkLogic 11's client offers neither, so fetching the JWKS fails with "
                          "XDMP-OAUTH ... SVC-SOCCONN 'sslv3 alert handshake failure' even though this machine connects. Put a TLS proxy "
                          "that accepts such clients in front of the IdP, or use MarkLogic 12")
        say("")
    elif profiles:
        missing("IdP endpoint, JWKS and TLS checks", "--no-probe given", "run without --no-probe from a machine that can reach the IdP")
    if a.token:
        cfg = next(iter(cfgs.values())) if len(cfgs) == 1 else (cfgs.get(a.external_security) or {})
        if len(cfgs) > 1 and not a.external_security:
            say("## Token check")
            say("")
            say("Several OAuth profiles exist; pass --external-security NAME so the token is compared with the right one.")
        else:
            try:
                analyse_token(a.token, cfg, jwks_doc, role_map, ext)
            except Exception as e:  # noqa: BLE001
                say("## Token check\n\nCould not read the token: %s\n" % e)
                check("FAIL", "token readable", str(e))
                missing("Token comparison", "the file could not be read (%s)" % str(e)[:100], "give a file with the access token")
    elif profiles:
        missing("Token comparison", "no --token given", "add --token <file> (an access token, or an Authorization header line, from a failed request)")
    if a.logs:
        analyse_logs_generic(c, "oauth", bound)
    elif profiles:
        missing("ErrorLog, AccessLog and trace-event status", "--logs not given",
                "add --logs --start <UTC time shortly before the test> (switch the trace events on first: ml-trace-events.py enable --preset oauth)")


# ---------------------------------------------------------------- LDAP
def run_ldap(c):
    a = c.a
    say("## LDAP external security profiles")
    say("")
    profiles = scan_profiles(c, "ldap")
    for n, props in profiles.items():
        say("### `%s`" % n)
        say("")
        say_table(scalar_rows(props))
        say("The bind password is never read out here; it is removed before saving.")
        say("")
        uri = first(props, "ldap-server-uri")
        for k in ("ldap-server-uri", "ldap-base", "ldap-attribute"):
            if not first(props, k):
                check("FAIL", "%s: %s is set" % (n, k), "empty")
        if str(first(props, "authorization")) == "ldap" and not any(first(props, k) for k in ("ldap-memberof-attribute", "ldap-member-attribute", "ldap-memberof")):
            check("INFO", "%s: group lookup attributes" % n, "authorization is `ldap`; no memberOf/member lookup attribute was found in the settings")
        for k, v in walk(props):
            if isinstance(v, str) and "BEGIN CERTIFICATE" in v:
                analyse_chain("`%s` %s" % (n, k), v)
        stored_ca = None
        for k, v in walk(props):
            if isinstance(v, str) and "BEGIN CERTIFICATE" in v and "private" not in k:
                stored_ca = (stored_ca or "") + v
        m = re.match(r"(ldaps?)://([^/:]+)(?::(\d+))?", uri or "")
        if not m:
            if uri:
                check("FAIL", "%s: ldap-server-uri is a valid URI" % n, "`%s`" % uri)
            continue
        scheme, host, port = m.group(1), m.group(2), m.group(3) or ("636" if m.group(1) == "ldaps" else "389")
        starttls = any(("start-tls" in k.lower() or "starttls" in k.lower()) and str(v).lower() in ("true", "1", "yes")
                       for k, v in walk(props) if not isinstance(v, (dict, list)))
        if getattr(a, "no_probe", False):
            continue
        say("#### Directory server %s:%s (checked from this machine)" % (host, port))
        say("")
        tls_lines_note()
        if scheme == "ldap" and not starttls:
            try:
                socket_ok = subprocess.run(["bash", "-c", "exec 3<>/dev/tcp/%s/%s" % (host, port)], capture_output=True, timeout=10).returncode == 0
            except Exception:  # noqa: BLE001
                socket_ok = None
            check("PASS" if socket_ok else "WARN", "%s: directory port reachable" % n, "%s:%s (plain LDAP)" % (host, port))
            check("WARN", "%s: connection is not encrypted" % n, "ldap:// without start TLS sends the bind password and user names in clear text")
            continue
        pr = tls_probe(host, port, starttls="ldap" if scheme == "ldap" else None)
        infos = analyse_tls_chain(c, "directory %s:%s" % (host, port), pr, host)
        if stored_ca and pr.get("certs"):
            with tempfile.NamedTemporaryFile("w", suffix=".pem", delete=False) as tf:
                tf.write(stored_ca)
                caf = tf.name
            pr2 = tls_probe(host, port, starttls="ldap" if scheme == "ldap" else None, cafile=caf)
            os.unlink(caf)
            if pr2.get("verify_code") is not None:
                check("PASS" if pr2["verify_code"] == 0 else "FAIL", "%s: directory certificate verifies with the CA stored in the profile" % n,
                      "verification result: %s (%s)" % (pr2["verify_code"], pr2.get("verify_msg")))
        elif pr.get("certs"):
            missing("CA certificate of profile `%s`" % n, "no certificate is stored in the profile",
                    "fine if MarkLogic's trusted certificate authorities already contain the directory's CA; otherwise store it in the profile")
            hit = ml_trust_of_chain(c, pr["certs"])
            check("PASS" if hit else "WARN", "%s: directory chain is trusted by MarkLogic" % n,
                  ("found in MarkLogic's certificate authorities: %s" % hit) if hit else "no certificate of the chain is in MarkLogic's trusted certificate authorities")
    bound = bound_servers(c, set(profiles)) if profiles else []
    role_map = None
    if profiles and any(str(first(p, "authorization")) == "ldap" for p in profiles.values()):
        role_map = load_role_map(c.api, c.out, c.errors)
    describe_users(c, "With authorization `internal`, the LDAP user is matched to a MarkLogic user's external name; with `ldap`, the user's group DNs are matched to the external names of roles.")
    if a.logs:
        analyse_logs_generic(c, "ldap", bound)
    elif profiles:
        missing("ErrorLog, AccessLog and trace-event status", "--logs not given",
                "add --logs --start <UTC time shortly before the test> (switch the trace events on first: ml-trace-events.py enable --preset ldap)")


# ---------------------------------------------------------------- HTTPS
TLS_ORDER = ["TLSv1", "TLSv1.1", "TLSv1.2", "TLSv1.3"]
WEAK_CIPHER = re.compile(r"RC4|3DES|DES-CBC|MD5|NULL|EXPORT|aNULL|eNULL|\bDES\b", re.I)


def tls_policy(sp, major):
    """Allowed TLS protocol range from the app server properties (MarkLogic 12 and 11 name them differently)."""
    if "ssl-min-allow-tls" in sp:
        return "minimum %s" % sp.get("ssl-min-allow-tls"), sp.get("ssl-min-allow-tls")
    flags = {"SSLv3": sp.get("ssl-disable-sslv3"), "TLSv1": sp.get("ssl-disable-tlsv1"), "TLSv1.1": sp.get("ssl-disable-tlsv1-1"),
             "TLSv1.2": sp.get("ssl-disable-tlsv1-2"), "TLSv1.3": sp.get("ssl-disable-tlsv1-3")}
    allowed = [k for k, v in flags.items() if v is False]
    return "allowed: %s" % (", ".join(allowed) or "see ssl-disable-* flags"), (next((k for k in TLS_ORDER if k in allowed), None))


def probe_versions(host, port):
    res = {}
    for v, flag in (("TLSv1", "-tls1"), ("TLSv1.1", "-tls1_1"), ("TLSv1.2", "-tls1_2"), ("TLSv1.3", "-tls1_3")):
        cmd = ["openssl", "s_client", "-connect", "%s:%s" % (host, port), flag, "-cipher", "ALL:@SECLEVEL=0"] if v in ("TLSv1", "TLSv1.1") else \
              ["openssl", "s_client", "-connect", "%s:%s" % (host, port), flag]
        if not re.match(r"^[\d.]+$|:", host):
            cmd += ["-servername", host]
        try:
            r = subprocess.run(cmd, input="", capture_output=True, text=True, timeout=15)
        except Exception:  # noqa: BLE001
            res[v] = "not tested"
            continue
        t = r.stdout + r.stderr
        # a failed handshake still prints "Protocol: TLSv1" (OpenSSL 3), but with "New, (NONE), Cipher is (NONE)"
        if re.search(r"New, %s, Cipher is (?!\(NONE\))\S+" % re.escape(v), t):
            res[v] = "accepted"
        elif re.search(r"unknown option|unsupported|no protocols available|Unable to set|invalid command", t, re.I):
            res[v] = "not testable with this openssl"
        else:
            res[v] = "refused"
    return res


def run_https(c):
    a = c.a
    servers = c.fetch("/manage/v2/servers?format=json", "servers-list.json", keep=False)
    items = []
    for k, v in walk(servers or {}):
        if k == "list-item":
            items.extend(v if isinstance(v, list) else [v])
    say("## HTTPS app servers")
    say("")
    chosen = []
    for it in items:
        if not isinstance(it, dict) or "nameref" not in it:
            continue
        nm, grp = it["nameref"], it.get("groupnameref", "Default")
        if a.appserver and nm != a.appserver:
            continue
        if a.group and grp != a.group:
            continue
        sp = c.fetch("/manage/v2/servers/%s/properties?group-id=%s&format=json" % (q(nm), q(grp)), "", keep=False)
        if not sp:
            continue
        if not a.appserver and not first(sp, "ssl-certificate-template"):
            continue
        c.save("server-%s-%s.json" % (grp, slug(nm)), sp)
        chosen.append((nm, grp, sp))
    if a.appserver and not chosen:
        sys.exit("ERROR: app server '%s' not found%s. Servers on this cluster: %s\nRun with --help for all options." % (
            a.appserver, " in group '%s'" % a.group if a.group else "", ", ".join(sorted({str(i.get('nameref')) for i in items if isinstance(i, dict)}))))
    if not chosen:
        say("No app server with a certificate template (HTTPS) was found.")
        say("")
        missing("HTTPS app servers", "none has an ssl-certificate-template", "pass --appserver <name> to check one anyway")
    probe_host = a.probe_host or a.host
    for nm, grp, sp in chosen:
        port = first(sp, "port")
        say("### `%s` (group `%s`, port %s)" % (nm, grp, port))
        say("")
        policy, minimum = tls_policy(sp, c.major)
        say_table([("authentication", str(first(sp, "authentication"))), ("ssl-certificate-template", str(first(sp, "ssl-certificate-template") or "none")),
                   ("TLS protocols", policy), ("ssl-ciphers", str(first(sp, "ssl-ciphers") or "default")),
                   ("ssl-ciphersuites (TLS 1.3)", str(first(sp, "ssl-ciphersuites") or ("n/a before MarkLogic 12" if c.major and c.major < 12 else "default"))),
                   ("ssl-require-client-certificate", str(first(sp, "ssl-require-client-certificate"))),
                   ("ssl-client-issuer-authority-verification", str(first(sp, "ssl-client-issuer-authority-verification"))),
                   ("ssl-hostname", str(first(sp, "ssl-hostname") or "not set"))])
        if not first(sp, "ssl-certificate-template"):
            check("WARN", "%s: HTTPS enabled" % nm, "no ssl-certificate-template: the app server does not use TLS")
            continue
        if minimum in ("TLSv1", "TLSv1.1", "SSLv3"):
            check("WARN", "%s: minimum TLS version" % nm, "%s is allowed; TLS 1.2 or later is recommended" % minimum)
        wc = WEAK_CIPHER.findall(str(first(sp, "ssl-ciphers") or ""))
        if wc:
            check("WARN", "%s: weak cipher suites enabled" % nm, "ssl-ciphers includes %s" % ", ".join(sorted(set(wc))))
        tmpl = first(sp, "ssl-certificate-template")
        td = c.fetch("/manage/v2/certificate-templates/%s?format=json" % q(tmpl), "certificate-template-%s.json" % slug(tmpl))
        tid = first(td or {}, "id")
        tcerts = template_report(c, tid, tmpl) if tid else []
        if getattr(a, "no_probe", False):
            continue
        say("#### Certificate served on %s:%s (checked from this machine)" % (probe_host, port))
        say("")
        tls_lines_note()
        cafile = a.server_ca
        pr = tls_probe(probe_host, port, cafile=cafile)
        infos = analyse_tls_chain(c, "app server %s (%s:%s)" % (nm, probe_host, port), pr, probe_host, check_ml_trust=False)
        if infos:
            served = norm_serial(infos[0].get("serial"))
            if tcerts:
                hit = [x for x in tcerts if x["serial"] == served]
                if hit:
                    check("PASS", "%s: the port serves the template's certificate" % nm,
                          "serial %s, %s" % (served[:16], "TEMPORARY" if hit[0]["temporary"] else "PERMANENT"))
                else:
                    check("WARN", "%s: the port does not serve a certificate of its template" % nm,
                          "served serial %s is not one of the template's (%s): the app server may need a restart after the certificate was replaced, or the port is behind a proxy/load balancer" % (
                              served[:16], ", ".join(x["serial"][:12] for x in tcerts)))
            if len(infos) == 1 and infos[0].get("self_signed"):
                if not any(x["temporary"] for x in tcerts):
                    check("INFO", "%s: the served certificate is self-signed" % nm, "clients must be told to trust it explicitly")
            elif len(infos) == 1 and not infos[0].get("self_signed"):
                check("WARN", "%s: server sends only its own certificate" % nm,
                      "the issuing (intermediate) certificate `%s` is not sent, so clients that do not already have it fail with 'unable to verify the first certificate'. "
                      "MarkLogic sends the chain it can build from its trusted certificate authorities: importing the issuing CA certificate there (Admin Interface > Security > Certificate Authorities, "
                      "or pki:insert-trusted-certificates in the Security database) made the port send leaf + intermediate at once (tested on 12.1.0). "
                      "Putting the intermediate in the certificate import itself is rejected (insert-host-certificates accepts one certificate: HTTP 400, PKI-BADCERTIFICATE)" % (infos[0].get("issuer") or "?"))
            if pr.get("client_cert_requested"):
                say("- The server asked for a client certificate during the handshake.")
                say("")
            elif str(first(sp, "ssl-require-client-certificate")).lower() == "true":
                say("- The settings require a client certificate; this openssl probe does not present one, so a failed request without one is expected.")
                say("")
            vers = probe_versions(probe_host, port)
            say("- Protocol versions this machine could negotiate: %s" % "; ".join("%s %s" % (k, v) for k, v in vers.items()))
            say("")
            for v, st in vers.items():
                if st == "accepted" and v in ("TLSv1", "TLSv1.1"):
                    check("WARN", "%s: %s is accepted" % (nm, v), "old protocol versions are accepted by the server")
            if minimum and vers.get("TLSv1.2") == "refused" and vers.get("TLSv1.3") == "refused":
                check("FAIL", "%s: TLS 1.2 or 1.3 accepted" % nm, "neither was negotiated")
    if chosen:
        duplicates_report(c)
    if not getattr(a, "no_probe", False) and chosen:
        cas = load_trusted_cas(c)
        say("MarkLogic's trusted certificate authorities (used for outgoing connections and client-certificate checks): %d" % len(cas))
        say("")
        missing("Client CA list of the app server (ssl-client-certificate-authorities)", "not available through the Management API",
                "Admin Interface > App Server > SSL Client Certificate Authorities, when client certificate authentication is used")
    elif getattr(a, "no_probe", False):
        missing("Live certificate and protocol checks", "--no-probe given", "run without --no-probe from a machine that can reach the app server port")
    if a.logs:
        analyse_logs_generic(c, "https", [{"name": nm, "group": grp, "port": first(sp, "port")} for nm, grp, sp in chosen])
    else:
        missing("ErrorLog TLS lines", "--logs not given", "add --logs --start <UTC time shortly before the test>")


# ---------------------------------------------------------------- SAML
def run_saml(c):
    a, api, out, fetch, save, errors = c.a, c.api, c.out, c.fetch, c.save, c.errors
    hosts = c.hosts
    # 2. external security objects
    listing = fetch("/manage/v2/external-security?format=json", "external-security-list.json")
    all_names = list_names(listing)
    if a.external_security and all_names and a.external_security not in all_names:
        sys.exit("ERROR: external security profile '%s' not found. Profiles on this cluster: %s\n"
                 "Run with --help for all options." % (a.external_security, ", ".join(all_names)))
    names = [a.external_security] if a.external_security else all_names
    cfgs = {}
    say("## External security objects")
    say("")
    for n in names:
        props = fetch("/manage/v2/external-security/%s/properties?format=json" % q(n), "", keep=False)
        if not props:
            continue
        auth = first(props, "authentication")
        if auth != "saml" and not a.external_security:
            continue
        save("external-security-%s.json" % re.sub(r"\W+", "_", n), props)
        cfg = {k: first(props, k) for k in ("saml-entity-id", "saml-destination", "saml-issuer", "saml-assertion-host",
                                           "saml-authn-signature", "saml-idp-certificate-authority", "saml-sp-certificate",
                                           "authorization", "cache-timeout", "authentication")}
        cfg["saml-attribute-names"] = find_all(props, "saml-attribute-name")
        cfg["saml-sp-private-key-set"] = bool(first(props, "saml-sp-private-key"))
        cfgs[n] = cfg
        say("### `%s`" % n)
        say("")
        if auth != "saml":
            say("Authentication type `%s`: this version only has SAML checks. The profile's settings, certificates and app servers are reported; secrets are removed." % auth)
            say("")
            say("| Setting | Value |")
            say("|---|---|")
            rows = 0
            for k, v in walk(props):
                if isinstance(v, (dict, list)) or v in (None, ""):
                    continue
                if SECRET_KEY_RE.search(k) or "BEGIN" in str(v) or len(str(v)) > 200:
                    continue
                say("| %s | `%s` |" % (k, str(v).replace("|", "\\|")))
                rows += 1
                if rows >= 80:
                    break
            say("")
            cfg["_cert_sha1"] = []
            for k, v in walk(props):
                if isinstance(v, str) and "BEGIN CERTIFICATE" in v:
                    cfg["_cert_sha1"] += [i["sha1"] for i in analyse_chain("`%s` %s" % (n, k), v)]
            if not cfg["_cert_sha1"]:
                missing("Certificates of profile `%s`" % n, "none stored in the profile", "n/a, or the profile uses a URL (for example a JWKS or issuer endpoint) instead")
            continue
        say("| Setting | Value |")
        say("|---|---|")
        for k in ("authentication", "authorization", "cache-timeout", "saml-entity-id", "saml-destination", "saml-issuer",
                  "saml-assertion-host", "saml-authn-signature"):
            say("| %s | `%s` |" % (k, cfg.get(k) if cfg.get(k) not in (None, "") else "not set"))
        say("| saml-attribute-names | `%s` |" % (", ".join(map(str, cfg["saml-attribute-names"])) or "none"))
        say("| saml-sp-certificate | %s |" % ("set" if cfg.get("saml-sp-certificate") else "not set"))
        say("| saml-sp-private-key | %s (value never collected) |" % ("set" if cfg["saml-sp-private-key-set"] else "not set"))
        say("")
        if auth == "saml":
            for k in ("saml-entity-id", "saml-destination", "saml-issuer"):
                if not cfg.get(k):
                    check("FAIL", "%s: %s is set" % (n, k), "empty")
            if cfg.get("saml-entity-id") and cfg.get("saml-issuer") and cfg["saml-entity-id"] == cfg["saml-issuer"]:
                check("WARN", "%s: entity-id differs from issuer" % n, "saml-entity-id is the IdP, saml-issuer is MarkLogic (SP); they are normally different")
            az = str(cfg.get("authorization"))
            if az != "saml":
                check("WARN", "%s: authorization is `saml`" % n,
                      "authentication is `saml` but authorization is `%s`. Guidance: SAML on MarkLogic 11.3.7 and 12.1 should use authorization `saml` (reported: `internal` is no longer supported after the "
                      "security hardening). In a test on 11.3.7 `internal` still granted roles when a role's external name equalled a Group value, so this setting alone is not what leaves a login "
                      "without roles; set `saml` anyway and check the role external names" % az)
        infos = analyse_chain("`%s` saml-idp-certificate-authority" % n, cfg.get("saml-idp-certificate-authority") or "")
        cfg["_cert_sha1"] = [i["sha1"] for i in infos]
        if not infos:
            missing("IdP certificate of profile `%s`" % n, "none is stored in saml-idp-certificate-authority",
                    "the IdP signing certificate has to be set in the profile; --idp-metadata shows the one the IdP publishes")
        if cfg.get("saml-sp-certificate"):
            analyse_chain("`%s` saml-sp-certificate" % n, cfg["saml-sp-certificate"])
    if not cfgs:
        say("No SAML external security object found (or it could not be read; see errors below).")
        say("")
        missing("External security profile", "none found" if not a.external_security else "could not be read",
                "check the profile name (Admin Interface > Security > External Security) and pass --external-security <name>")

    # 3. app servers
    say("## App servers using these objects")
    say("")
    servers = fetch("/manage/v2/servers?format=json", "servers-list.json")
    seen = False
    bound = []   # (server, group, port)
    items = []
    if servers:
        for k, v in walk(servers):
            if k == "list-item":
                items.extend(v if isinstance(v, list) else [v])
    for it in items:
        if not isinstance(it, dict) or "nameref" not in it:
            continue
        nm, grp = it["nameref"], it.get("groupnameref", "Default")
        sp = fetch("/manage/v2/servers/%s/properties?group-id=%s&format=json" % (q(nm), q(grp)), "server-%s-%s.json" % (grp, re.sub(r"\W+", "_", nm)), keep=False)
        if not sp:
            continue
        used = [str(x) for x in find_all(sp, "external-security")]
        if not any(u in cfgs for u in used):
            continue  # only app servers that use a SAML object are saved
        save("server-%s-%s.json" % (grp, re.sub(r"\W+", "_", nm)), sp)
        seen = True
        bound.append((nm, grp, first(sp, "port")))
        say("- `%s` (group `%s`, port %s): authentication `%s`, internal-security `%s`, external-security `%s`, TLS template `%s`" % (
            nm, grp, first(sp, "port"), first(sp, "authentication"), first(sp, "internal-security"), ", ".join(used),
            first(sp, "ssl-certificate-template", default="none")))
        if first(sp, "authentication") != "application-level" and first(sp, "authentication") != "saml":
            check("INFO", "app server %s authentication" % nm, "authentication is `%s`; SAML relies on external-security being bound" % first(sp, "authentication"))
    if not seen:
        say("None found (the object may not be bound to an app server, or the server list could not be read).")
        check("WARN", "SAML external security is bound to an app server", "no app server referenced a SAML object")
        missing("App servers using the profile", "no app server references it (it may be unused, or the server list could not be read)",
                "check the app server's authentication settings")
    say("")

    # 4. users and external names
    ext_names = None
    if a.user_name:
        say("## Users, roles and external names")
        say("")
        allmap = {}
        role_cache = {}
        role_priv = {}

        def role_ext(role, depth=0):
            if role in role_cache or depth > 5:
                return
            rp = fetch("/manage/v2/roles/%s/properties?format=json" % q(role), "role-%s.json" % re.sub(r"\W+", "_", role))
            role_cache[role] = ([str(x) for x in find_all(rp or {}, "external-name")], [str(x) for x in find_all(rp or {}, "role")])
            privs = []
            for pr in find_all(rp or {}, "privilege"):
                if isinstance(pr, str):
                    privs.append(pr)
            role_priv[role] = [str(x).rsplit("/", 1)[-1] for k, x in walk(rp or {}) if k == "action"]
            for en in role_cache[role][0]:
                allmap.setdefault(en, []).append("role " + role)
            for r in role_cache[role][1]:
                role_ext(r, depth + 1)

        for un in a.user_name:
            up = fetch("/manage/v2/users/%s/properties?format=json" % q(un), "user-%s.json" % re.sub(r"\W+", "_", un))
            if not up:
                say("- `%s`: could not be read (see errors)" % un)
                check("FAIL", "user %s exists" % un, "could not read user properties")
                continue
            ens = [str(x) for x in find_all(up, "external-name")]
            roles = [str(x) for x in find_all(up, "role")]
            for en in ens:
                allmap.setdefault(en, []).append("user " + un)
            for r in roles:
                role_ext(r)
            say("- `%s`: external names %s; roles %s" % (un, ens or "none", roles or "none"))
            for r in roles:
                if r in role_cache:
                    say("  - role `%s` external names: %s; inherits %s; privileges: %s" % (
                        r, role_cache[r][0] or "none", role_cache[r][1] or "none", ", ".join(role_priv.get(r, [])[:25]) or "none"))
        say("")
        say("The roles of a SAML login come from the assertion's Group values matched to the external names of roles (tested on 11.3.7 with authorization `saml` and with `internal`). The user's own roles and external names shown above are NOT used for a SAML login.")
        say("")
        ext_names = {"all": allmap}

    if not a.user_name:
        missing("User and role external names", "no --user-name given",
                "add --user-name <MarkLogic user the login maps to>" + ("; the external names of all roles were still collected" if any(c.get("authorization") == "saml" for c in cfgs.values()) else ""))

    # 5. metadata
    md = None
    if a.idp_metadata:
        say("## IdP metadata check")
        say("")
        text, err = load_metadata(a.idp_metadata, a)
        if err:
            say("Could not read the metadata: " + err)
            check("FAIL", "IdP metadata readable", err)
            missing("IdP metadata comparison", "the metadata could not be read (%s)" % err[:100], "check the file name or URL; use --metadata-insecure for an untrusted TLS certificate")
        else:
            try:
                md = parse_metadata(text)
            except ET.ParseError as e:
                md = None
                say("The metadata is not valid XML: %s" % e)
                check("FAIL", "IdP metadata is valid XML", str(e))
        if md:
            with open(os.path.join(out, "idp-metadata.xml"), "w") as f:
                f.write(text)
            say("- entityID: `%s`" % md["entity_id"])
            for b, loc in md["sso"]:
                say("- SingleSignOnService %s: `%s`" % (b.rsplit(":", 1)[-1], loc))
            mdinfo = [cert_info(base64.b64decode(c + "=" * (-len(c) % 4))) for c in md["certs"]]
            for i in mdinfo:
                say("- signing certificate: `%s`, expires %s, SHA-1 `%s`" % (i.get("subject"), fmt_dt(i.get("not_after")), i["sha1"]))
            if md["multiple"]:
                check("WARN", "metadata holds several EntityDescriptors", "only the first was used")
            if md["valid_until"]:
                vu = parse_iso(md["valid_until"])
                if vu and vu < NOW:
                    check("WARN", "metadata validUntil has passed", md["valid_until"])
            for n, cfg in cfgs.items():
                if cfg.get("saml-entity-id"):
                    check("PASS" if cfg["saml-entity-id"] == md["entity_id"] else "FAIL", "%s: saml-entity-id = metadata entityID" % n,
                          "config `%s` / metadata `%s`" % (cfg["saml-entity-id"], md["entity_id"]))
                if cfg.get("saml-destination"):
                    locs = [l for _, l in md["sso"]]
                    check("PASS" if cfg["saml-destination"] in locs else "FAIL", "%s: saml-destination is a metadata SSO URL" % n,
                          "config `%s` / metadata %s" % (cfg["saml-destination"], ", ".join(locs) or "none"))
                mdfp = {i["sha1"] for i in mdinfo}
                if cfg["_cert_sha1"] and mdfp:
                    hit = set(cfg["_cert_sha1"]) & mdfp
                    check("PASS" if hit else "FAIL", "%s: stored IdP certificate is in the metadata" % n,
                          "stored %s / metadata %s" % (", ".join(cfg["_cert_sha1"]), ", ".join(sorted(mdfp))))
                    extra = mdfp - set(cfg["_cert_sha1"])
                    if hit and extra:
                        check("INFO", "%s: metadata lists other signing certificates" % n,
                              "%d not stored in MarkLogic (a rollover certificate?). Tokens signed by them would be rejected" % len(extra))
        say("")

    has_saml = any(c.get("authentication") == "saml" for c in cfgs.values())
    if cfgs and not has_saml:
        missing("IdP metadata and SAML response comparison", "the profile is not a SAML profile (authentication `%s`)" % ", ".join(sorted({str(c.get("authentication")) for c in cfgs.values()})),
                "not applicable; OAuth-specific checks (issuer, JWKS, token claims) are not implemented in this version")
    elif not a.idp_metadata:
        missing("IdP metadata comparison", "no --idp-metadata given",
                "add --idp-metadata <file or https://... URL>; the entity ID, destination and certificate stored in the profile are listed above")
    if has_saml and not a.saml_response:
        missing("SAML response comparison", "no --saml-response given",
                "add --saml-response <file> (a captured SAMLResponse or an authorization header line)")
    # 6. response
    if a.saml_response:
        try:
            xml_text = load_response(a.saml_response)
            cfg = next(iter(cfgs.values()), {}) if len(cfgs) == 1 else (cfgs.get(a.external_security) or {})
            if len(cfgs) > 1 and not a.external_security:
                say("## SAML response check")
                say("")
                say("Several SAML objects exist; pass --external-security NAME so the response is compared with the right one.")
            else:
                analyse_response(xml_text, cfg, md, ext_names)
        except Exception as e:  # noqa: BLE001 - report, do not crash the whole gather
            say("## SAML response check\n\nCould not read the response: %s\n" % e)
            check("FAIL", "SAML response readable", str(e))
            missing("SAML response comparison", "the file could not be read (%s)" % str(e)[:100], "give a file holding the base64 SAMLResponse, the XML, or an authorization header line")

    if not a.logs:
        missing("ErrorLog, AccessLog and trace-event status", "--logs not given",
                "add --logs --start <UTC time shortly before the test> (switch the trace events on first with ml-trace-events.py, preset saml or oauth)")
    # 7. trace events, role map and logs
    if a.logs or cfgs:
        role_map = load_role_map(api, out, errors)
    else:
        role_map = None
    if role_map is not None and cfgs:
        if not role_map:
            check("FAIL", "a role has an external name to receive SAML roles",
                  "no role has an external name, so a SAML login can never be given a role: give a role an external name equal to a Group value of the assertion")
        else:
            check("PASS", "roles with external names exist", "%d external name(s): %s" % (len(role_map), ", ".join(sorted(role_map)[:6]) + (" ..." if len(role_map) > 6 else "")))
    if a.logs:
        hostnames = list_names(hosts)
        analyse_logs(a, api, out, cfgs, bound, hostnames, role_map, errors)


def finish(c):
    out, errors = c.out, c.errors
    # summary
    say("## Not collected")
    say("")
    if NOT_COLLECTED:
        say("These parts were skipped because the input was not given or the data was not available. Everything else in this report was collected.")
        say("")
        say("| Not collected | Why | How to add it |")
        say("|---|---|---|")
        for w, why, how in NOT_COLLECTED:
            say("| %s | %s | %s |" % (w.replace("|", "\\|"), why.replace("|", "\\|"), how.replace("|", "\\|")))
        REPORT[4:4] = ["**%d part(s) were not collected**; see the section \"Not collected\" near the end." % len(NOT_COLLECTED), ""]
    else:
        say("Nothing was skipped.")
    say("")
    order = {"FAIL": 0, "WARN": 1, "INFO": 2, "PASS": 3}
    say("## Check results")
    say("")
    if CHECKS:
        say("| Result | Check | Detail |")
        say("|---|---|---|")
        for r, n, d in sorted(CHECKS, key=lambda c: order[c[0]]):
            say("| **%s** | %s | %s |" % (r, n, d.replace("|", "\\|")))
    else:
        say("No checks could be run.")
    say("")
    if errors:
        say("## Calls that failed")
        say("")
        for e in errors:
            say("- " + e)
        say("")
    say("Only the properties named above were read. The SP private key, passwords and secrets are removed before saving.")
    with open(os.path.join(out, "SUMMARY.md"), "w") as f:
        f.write("\n".join(REPORT) + "\n")
    shutil.make_archive(out, "zip", out)
    fails = sum(1 for c in CHECKS if c[0] == "FAIL")
    print("Wrote %s/SUMMARY.md and %s.zip  (%d FAIL, %d WARN)" % (out, out, fails, sum(1 for c in CHECKS if c[0] == "WARN")))


# ---------------------------------------------------------------- command line
def build_parser():
    top = Parser(prog="ml-security-gather.py", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter,
                 allow_abbrev=False)
    sub = top.add_subparsers(dest="area", metavar="AREA", parser_class=Parser)
    sub.required = True

    base = argparse.ArgumentParser(add_help=False)
    base.add_argument("--host", required=True, help="MarkLogic host name (any host of the cluster)")
    base.add_argument("--port", default="8002", help="Management API port (default 8002)")
    base.add_argument("--scheme", default="https", choices=["http", "https"], help="Management API scheme (default https)")
    env_user = os.environ.get("MARKLOGIC_USER")
    base.add_argument("--user", default=env_user, required=not env_user,
                      help="MarkLogic user with the admin role: the user `admin` or any other administrator account "
                           "(default: the MARKLOGIC_USER environment variable)")
    base.add_argument("--cacert", metavar="CA.PEM", help="CA bundle used to verify the Management API certificate")
    base.add_argument("--insecure", action="store_true", help="do not verify the Management API certificate")
    base.add_argument("--out", help="output directory (default ./<area>-gather-<timestamp>)")

    logs = argparse.ArgumentParser(add_help=False)
    logs.add_argument("--logs", action="store_true", help="also read the ErrorLog (trace events) and the app server AccessLog for a time window")
    logs.add_argument("--minutes", type=int, default=60, help="with --logs: how far back to look (default 60)")
    logs.add_argument("--start", type=utc_arg, metavar="UTC_TIME",
                      help="with --logs: window start in UTC, e.g. 2026-01-15T09:00:00Z; a time without a zone means UTC and an offset such as +01:00 is converted (overrides --minutes)")
    logs.add_argument("--end", type=utc_arg, metavar="UTC_TIME", help="with --logs: window end in UTC, same formats as --start (default: now)")

    prof = argparse.ArgumentParser(add_help=False)
    prof.add_argument("--external-security", metavar="NAME", help="name of the external security profile to read (default: every profile of this area)")
    prof.add_argument("--user-name", action="append", default=[], help="MarkLogic user to look up; repeat for several")

    probe = argparse.ArgumentParser(add_help=False)
    probe.add_argument("--no-probe", action="store_true", help="do not connect to other servers (IdP, directory, app server port) from this machine")

    subs = {}

    def add(area, helptext, desc, parents):
        sp = sub.add_parser(area, help=helptext, description=desc, parents=parents,
                            formatter_class=argparse.RawDescriptionHelpFormatter, allow_abbrev=False)
        subs[area] = sp
        return sp

    s = add("saml", "SAML external security profile", """SAML: read the profile, its certificates, the app servers using it, the user/role external names, the IdP metadata,
a captured SAML response and the SAML trace in the logs. Only --host and --user are required.

Smallest useful run:
  ml-security-gather.py saml --host ml1.example.com --user admin --external-security <profile>
Fuller run (login problem):
  ml-security-gather.py saml --host ml1.example.com --user admin --external-security <profile> \\
      --user-name <failing MarkLogic user> --idp-metadata <file or https://...> \\
      --saml-response response.txt --logs --start 2026-01-15T09:00:00Z""", [base, prof, logs])
    s.add_argument("--idp-metadata", help="IdP metadata file or URL")
    s.add_argument("--saml-response", help="file holding a captured SAMLResponse (XML, base64, or an authorization header line)")
    s.add_argument("--metadata-insecure", action="store_true", help="do not verify the TLS certificate of a metadata URL")

    s = add("oauth", "OAuth external security profile (MarkLogic 11: Resource server; MarkLogic 12 also Authorization code)", """OAuth: read the profile, the app servers using it, the IdP discovery document and JWKS, the IdP's TLS chain (and whether
MarkLogic trusts it), a captured access token and the OAuth trace in the logs. Only --host and --user are required.

Smallest useful run:
  ml-security-gather.py oauth --host ml1.example.com --user admin --external-security <profile>
Fuller run (token rejected):
  ml-security-gather.py oauth --host ml1.example.com --user admin --external-security <profile> \\
      --token token.txt --logs --start 2026-01-15T09:00:00Z""", [base, prof, logs, probe])
    s.add_argument("--token", metavar="FILE", help="file holding a captured access token (JWT) or an Authorization: Bearer header line")

    add("ldap", "LDAP external security profile", """LDAP: read the profile, its certificates, check the directory server's TLS from this machine and against MarkLogic's
trusted CAs, the user/role external names and the LDAP trace in the logs. Only --host and --user are required.

Smallest useful run:
  ml-security-gather.py ldap --host ml1.example.com --user admin --external-security <profile>
Fuller run (login problem):
  ml-security-gather.py ldap --host ml1.example.com --user admin --external-security <profile> \\
      --user-name <MarkLogic user> --logs --start 2026-01-15T09:00:00Z""", [base, prof, logs, probe])

    s = add("https", "HTTPS-enabled app server (TLS settings and the certificate it serves)", """HTTPS: read the app server's TLS settings and certificate template, and look at what the port really serves: the certificate
chain, host name match, expiry, protocol versions and cipher. Without --appserver every app server that has a certificate
template is checked. Only --host and --user are required.

Smallest useful run:
  ml-security-gather.py https --host ml1.example.com --user admin --appserver <app server name>
Private CA (check the served chain against it):
  ml-security-gather.py https --host ml1.example.com --user admin --appserver <name> --server-ca my-ca.pem""", [base, logs, probe])
    s.add_argument("--appserver", metavar="NAME", help="check this app server (default: every app server with a certificate template)")
    s.add_argument("--group", help="group of the app server (default: any)")
    s.add_argument("--server-ca", metavar="CA.PEM", help="CA bundle for verifying the certificate the app server presents")
    s.add_argument("--probe-host", metavar="HOST", help="host name to connect to for the live TLS check (default: --host)")
    return top, subs


def main():
    top, subs = build_parser()
    a, extra = top.parse_known_args()
    if extra:
        # argparse would report this from the top-level parser; show the help of the area instead
        subs[a.area].error("unrecognized arguments: %s" % " ".join(extra))
    c = setup(a, subs[a.area], a.area)
    {"saml": run_saml, "oauth": run_oauth, "ldap": run_ldap, "https": run_https}[a.area](c)
    finish(c)


if __name__ == "__main__":
    main()
