Example output of ml-security-gather.py (sanitised: host names, IdP name and client IP replaced with example.com values).

Produced on a MarkLogic 12.1.0 test system with a SAML IdP, with SAML trace events on, using a test user that has only
the qconsole-user role. The time window contains two test logins:
  1. a login replaying a valid assertion  -> accepted by MarkLogic, then HTTP 403 (the user's roles lack a privilege for the URL)
  2. a login with a tampered assertion    -> HTTP 401, "signature is invalid" (the same pattern a certificate mismatch gives)
The run also used --user-name, --idp-metadata and --saml-response, so the report includes the metadata and token comparisons.

Files:
  SUMMARY.md, SUMMARY.html  the same report in Markdown and HTML (open the HTML in a browser); start at "Check results" at the end (FAIL lines first)
  ErrorLog-saml-*.txt   the SAML lines from ErrorLog.txt (long values removed)
  AccessLog-*.txt       the app server access log lines in the window (query strings removed)
A real run also creates the raw JSON of each call and a .zip of the whole folder, which is what is sent to Support.
