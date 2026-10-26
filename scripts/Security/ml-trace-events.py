#!/usr/bin/env python3
"""Enable, disable or list MarkLogic trace events on a group, using the Management API.

Generic: works for any trace event (SAML, OAuth, LDAP, ...), not only SAML.

Examples
  export MARKLOGIC_PASS='...'            # the password is never taken from the command line
  ml-trace-events.py status  --host ml1.example.com --user admin
  ml-trace-events.py enable  --host ml1.example.com --user admin --preset saml
  ml-trace-events.py enable  --host ml1.example.com --user admin --event "SAML" --event "SAML Response"
  ml-trace-events.py disable --host ml1.example.com --user admin --preset saml

Reproduce the problem between "enable" and "disable", then send the ErrorLog.txt for that period.
Trace events are written to ErrorLog.txt at Info level (no change to the file log level is needed).

Requires python3 (standard library only) and curl. Changes are made to one group; run once per group
if the app servers are in different groups. Trace events add log volume: disable them when finished.

What it changes
  enable : adds the named events to the group's trace events and turns the trace mechanism on.
  disable: removes only the named events; it turns the mechanism off again only if this script was the
           one that turned it on (recorded in .ml-trace-events-state.json in the current directory).
  Events that were already configured are never touched.

Verified against MarkLogic 12.1.0: the group properties hold the events as a flat list "event": ["SAML", ...]
plus "events-activated"; the server does not validate event names (a typo is accepted silently);
a PUT replaces the whole list, which is why the script always sends the full list.
"""
import argparse
import json
import os
import subprocess
import sys
import urllib.parse

PRESETS = {
    # SAML plus the generic external-login event that records the outcome of each login
    "saml": ["SAML", "SAML Response", "External Authenticate"],
    "oauth": ["OAuth", "OAuth Status", "OAuth Communications", "OAuth JSON Processing", "External Authenticate"],
    "ldap": ["External Authenticate", "LDAP", "LDAP Search"],
}
STATE_FILE = ".ml-trace-events-state.json"


def die(msg):
    sys.exit("ERROR: " + msg)


def curl(args, method, path, body=None):
    url = "%s://%s:%s%s" % (args.scheme, args.host, args.port, path)
    password = os.environ.get("MARKLOGIC_PASS")
    if password is None:
        die("set the MARKLOGIC_PASS environment variable (passwords are not accepted on the command line)")
    cmd = ["curl", "-sS", "--anyauth", "-K", "-", "-X", method, "-w", "\n%{http_code}",
           "-H", "Accept: application/json", "--max-time", "60"]
    if args.cacert:
        cmd += ["--cacert", args.cacert]
    if args.insecure:
        cmd.append("-k")
    if body is not None:
        cmd += ["-H", "Content-Type: application/json", "--data-binary", json.dumps(body)]
    cmd.append(url)
    # credentials go through stdin so they do not appear in the process list
    cfg = 'user = "%s:%s"\n' % (args.user.replace("\\", "\\\\").replace('"', '\\"'),
                                password.replace("\\", "\\\\").replace('"', '\\"'))
    r = subprocess.run(cmd, input=cfg, capture_output=True, text=True)
    if r.returncode != 0:
        hint = {6: "check --host", 7: "cannot connect: check --host, --port (normally 8002) and --scheme",
                60: "the certificate is not trusted: use --cacert <ca.pem> (or --insecure for a one-off test)",
                35: "TLS handshake failed: is the port plain HTTP? try --scheme http",
                }.get(r.returncode, "check --host, --port and --scheme")
        die("curl failed (%d): %s\n%s. Run with --help for all options." % (r.returncode, r.stderr.strip(), hint))
    text, _, code = r.stdout.rpartition("\n")
    return int(code), text


def props_path(group):
    return "/manage/v2/groups/%s/properties?format=json" % urllib.parse.quote(group, safe="")


def get_props(args):
    code, text = curl(args, "GET", props_path(args.group))
    if code != 200:
        hint = {401: " The user name or password was refused (check --user and MARKLOGIC_PASS).",
                403: " The user is not allowed to read the group; run as a MarkLogic user with the admin role (--user).",
                404: " The group '%s' does not exist: check --group." % args.group}.get(code, "")
        die("GET group properties returned HTTP %s: %s%s" % (code, text[:300], hint))
    return json.loads(text)


def current_events(props):
    """The group's trace events: GET returns a flat list of names under "event" (absent when empty)."""
    ev = props.get("event") or []
    return [ev] if isinstance(ev, str) else list(ev)


def put(args, body):
    code, text = curl(args, "PUT", "/manage/v2/groups/%s/properties" % urllib.parse.quote(args.group, safe=""), body)
    if code not in (200, 204):
        die("PUT group properties returned HTTP %s: %s" % (code, text[:400]))


def load_state():
    try:
        with open(STATE_FILE) as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def save_state(state):
    with open(STATE_FILE, "w") as f:
        json.dump(state, f, indent=2)


def show(props, group):
    ev = current_events(props)
    print("Group: %s   trace mechanism (events-activated): %s" % (group, "ON" if props.get("events-activated") else "off"))
    if not ev:
        print("  no trace events configured")
    for e in ev:
        print("  " + e)


class Parser(argparse.ArgumentParser):
    """Prints the full documentation, then the error, when the command line is wrong."""

    def error(self, message):
        self.print_help(sys.stderr)
        sys.stderr.write("\nERROR: %s\n" % message)
        sys.exit(2)


def main():
    p = Parser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter, allow_abbrev=False)
    p.add_argument("action", choices=["enable", "disable", "status"])
    p.add_argument("--host", required=True)
    p.add_argument("--port", default="8002", help="Management API port (default 8002)")
    p.add_argument("--scheme", default="https", choices=["http", "https"])
    env_user = os.environ.get("MARKLOGIC_USER")
    p.add_argument("--user", default=env_user, required=not env_user,
                   help="MarkLogic user with the admin role: the user `admin` or any other administrator account (default: the MARKLOGIC_USER environment variable)")
    p.add_argument("--group", default="Default", help="group name (default: Default)")
    p.add_argument("--event", action="append", default=[], help="trace event name; repeat for several")
    p.add_argument("--preset", action="append", default=[], choices=sorted(PRESETS), help="named set of events")
    p.add_argument("--cacert", help="CA bundle used to verify the Management API certificate")
    p.add_argument("--insecure", action="store_true", help="do not verify the Management API certificate (curl -k)")
    p.add_argument("--dry-run", action="store_true", help="show the change without applying it")
    args = p.parse_args()

    names = list(args.event)
    for pr in args.preset:
        names += PRESETS[pr]
    names = list(dict.fromkeys(names))
    if args.action != "status" and not names:
        p.error("give at least one --event or --preset for %s" % args.action)
    if os.environ.get("MARKLOGIC_PASS") is None:
        if sys.stdin.isatty():
            import getpass
            os.environ["MARKLOGIC_PASS"] = getpass.getpass("Password for %s: " % args.user)
        else:
            p.error("set the MARKLOGIC_PASS environment variable, for example: export MARKLOGIC_PASS='<password>' "
                    "(passwords are not accepted on the command line)")

    props = get_props(args)
    if args.action == "status":
        show(props, args.group)
        return

    cur = current_events(props)
    activated = bool(props.get("events-activated", False))
    state = load_state()
    gkey = "%s|%s" % (args.host, args.group)
    gstate = state.setdefault(gkey, {"activated_by_script": False})

    # Verified on MarkLogic 12.1.0: PUT replaces the whole list, so send the complete new list.
    if args.action == "enable":
        new = cur + [n for n in names if n not in cur]
        body = {"event": new}
        if not activated:
            body["events-activated"] = True
            gstate["activated_by_script"] = True
        print("Enabling:", ", ".join(names), "(already present: %s)" % (", ".join(n for n in names if n in cur) or "none"))
    else:
        new = [n for n in cur if n not in names]
        body = {"event": new}
        if not new and gstate["activated_by_script"]:
            body["events-activated"] = False
            gstate["activated_by_script"] = False
        print("Disabling:", ", ".join(names))

    if args.dry_run:
        print("Dry run. Would PUT to /manage/v2/groups/%s/properties:" % args.group)
        print(json.dumps(body, indent=2))
        return
    put(args, body)
    save_state(state)
    show(get_props(args), args.group)


if __name__ == "__main__":
    main()
