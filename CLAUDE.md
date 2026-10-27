# Rules for Claude agents in this repository

Two Claude agents cooperate. Work only in your own area.
- **Scripts agent (this repository)** owns the must-gather scripts, their tests, the copy in the support skill (via `scripts/Security/sync-support-scripts.sh`) and this repository's documentation.
- **Labs agent** owns the private labs repository and the lab systems. Do NOT edit that repository, its reference reports or the lab objects, and do not commit to it, even for a small fix.

Communication goes through the handoff folder `~/Projects/lab-handoff/` (outside every repository): read its README.
- After testing the scripts against the labs, write `results/YYYY-MM-DD-<area>.md` (template there).
- To ask for a lab change, a new lab or a regenerated reference report, write `requests/NNNN-title.md`. Check `done/` for answers.
- The lab catalogue is `lab-manifest.json` in the labs repository; read it, never edit it. Lab details (hosts, ports, object names, passwords) must never be copied into this public repository: use example.com in docs and tests.

Git: branch before committing, never commit to `main`, commit and push only when the owner asks, commit messages end with `Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>`. Git author for this repository: `claude-scripts`.
Run the unit tests and `sync-support-scripts.sh` after changing the scripts.

 ## Agents and shared tools
    The registry of agents, request naming and the test-window rule are in ~/Projects/lab-handoff/agents.md: read it. Your agent id is `scripts-agent`.
    Certificates and keys for tests are obtained with ~/Projects/lab-handoff/tools/ca-cert.sh (see tools/README.md in that folder), with your own token; they are written under ~/Projects/lab-certs/scripts-agent/, never into a repository. Do not commit certificates, keys, tokens or the CA address; unit tests use example.com and a local mock or a certificate made at test time.
    For anything the token does not allow, write a request addressed `To: ca-agent`. Run logins on the lab systems only while ~/Projects/lab-handoff/locks/lab-window.md exists and names you or the labs agent's window for your test.
