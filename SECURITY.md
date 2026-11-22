# Security policy

## Supported versions

The public `0.1.x` line is supported for security fixes. Older or forked versions
are supported on a best-effort basis.

## Report a vulnerability in `sak`

Open a **private GitHub security advisory**:

<https://github.com/Brymes/swiss-army-knife-skills/security/advisories/new>

If advisories are unavailable, open a minimal public issue asking the maintainer
for a private channel; do not include the exploit or a secret in the public issue.

Include:

- the affected version or commit;
- the command or code path;
- a minimal reproduction;
- the observed effect and expected behavior;
- whether the issue needs a target, Docker, a model or a specific harness;
- sanitized logs and a suggested fix, if you have one.

Do not include real tokens, cookies, passwords, keys, customer data or a live
third-party target. Use loopback fixtures and documented lab defaults.

## What is in scope

- the `sak` CLI and Python package;
- the catalog, schemas and adapters;
- the `swiss-army-knife` skill and install scripts;
- evidence/report integrity, secret masking and scope enforcement;
- the offline fixture and benchmark harness.

Out of scope:

- vulnerabilities in DVWA, vuln-bank or another target — report those in the
  target's own project or in the assessment report;
- behavior of a third-party model, harness, MCP server or engine;
- findings caused by running outside an authorized scope;
- denial-of-service or destructive payloads against a real host.

## Disclosure

The maintainer will acknowledge a private report, reproduce it on a loopback lab,
and coordinate a fix and disclosure date. Please allow a reasonable window before
public disclosure.

## Safe use

`sak` is for authorized assessments only. Active tools require a written
`scope.md`; the default targets are loopback fixtures. The project is not a license
to test systems you do not own or have written permission to test.
