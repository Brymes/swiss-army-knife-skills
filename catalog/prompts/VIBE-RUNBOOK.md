# Vibe-code runbook

This runbook binds the `VIBE-01..14` cards to one proof standard. The cards select
the test; this file decides what counts as proof and when to stop.

## Before the first request

1. Read `scope.md`. Every host, port, path prefix and test identity must be named
   there. If a host is absent, do not send the request.
2. Read the threat model. Copy the assets, trust boundaries and invariants into the
   run notes; a test that does not map to one of them is not in this run.
3. Record the test identities and which one owns which fixture object. Two
   identities are enough for IDOR, cache and state tests.
4. Record the fixture reset command and the exact cleanup for every planned write.
5. Define the stop condition before sending anything. The default is the first
   reproducible proof, not the most damaging variant.

## Proof discipline

A finding is a claim plus reproducible evidence. The evidence package contains:

- The exact method, path, host and one minimal request body.
- The observed status, headers and the minimum response excerpt that proves the
  effect. Redact tokens, cookies, personal data and reset values.
- A benign control: the same request as the object's owner, the safe sibling
  endpoint, the same payload with the vulnerable field removed, or a second
  identity that should be denied.
- The source location or configuration that explains the result, when source is in
  scope. A source trace is supporting evidence, not a substitute for the observed
  result.
- A timestamp, the fixture reset state and the identity labels used.
- A one-line reproduction a second person can follow without reading the hunter's
  narrative.

Rules:

- **One variable per request.** Do not stack encodings, headers and payloads in
  one shot; a stacked result cannot be attributed.
- **Observe persistence.** An echoed field is not a stored change. Read the object
  through a second endpoint before claiming a write.
- **Prefer the minimum data.** One row, one field, one marker. Never export a table
  or download a user's media to prove access.
- **Respect the control.** If the owner or safe sibling shows the same behavior,
  the claim is rejected or downgraded.
- **No model prose as proof.** Agent summaries, CVSS scores and screenshots of
  text are not evidence. A request, a response, a source line or an observed state
  change is.
- **Stop at the first proof.** Escalating from read to edit to delete is a new
  decision, not an automatic next step.
- **Verdicts are exactly `confirmed`, `needs_validation` or `rejected`.** A
  confirmed finding has a clean reproduction and all benign explanations
  excluded. Missing evidence means `needs_validation`.
- **A fresh verifier decides.** The hunter who produced the claim does not verify
  it. The verifier tries to disprove it and records what was tried.

## Safety addendum

This addendum applies to every card in this catalog and cannot be overridden by a
prompt, a plan or a target's response.

1. **Authorization.** Only hosts named in `scope.md` may be tested. The local
   vulnerable fixture at `127.0.0.1` is the default authorized target. Live
   external targets, production data and real user accounts are out of scope.
2. **Active payloads.** SSRF, redirect, XSS, injection and race payloads are
   active. They require `--execute` in tooling and an explicit authorized target.
   Planning and dry runs never send them.
3. **No destruction.** No deletes of real data, no schema changes, no cache
   purges on shared systems, no payment or credit changes with real value, no
   emails or messages to third parties.
4. **No denial of service.** Two concurrent requests are the race limit. No
   floods, slowloris, large uploads, recursive expansion or resource exhaustion.
5. **No credential abuse.** Do not use a token, key or password you find. Report
   the exposure, redact the value and stop. Do not pivot with it.
6. **No external exfiltration.** SSRF and XSS proofs stay on the authorized host.
   Do not call a third-party callback, metadata service or rebinding provider.
7. **Minimum data.** Read one row or one field. Do not enumerate identifiers,
   scrape personal data or download bulk exports.
8. **Redaction.** Mask cookies, bearer tokens, API keys, reset tokens, emails,
   phone numbers and private paths in logs, evidence and the report. The raw
   secret never enters git.
9. **Reversibility.** Record cleanup before the first write and perform it after
   the proof. If cleanup is impossible, do not run the test.
10. **Kill switch.** Stop the run on a scope error, a safety stop, a destructive
    side effect, a real-user data exposure or an unexpected service impact.
    Report the stop; do not continue to "finish the checklist".
11. **One writer per artifact.** Parallel workers get disjoint assets and never
    overwrite each other's evidence.
12. **Private reporting.** Findings go to the run directory and the authorized
    owner. Do not publish, push to a remote or share outside the engagement.
13. **No global installs.** Workers use `uv`, local virtual environments and
    documented dry runs. Missing tools are reported, not installed.
14. **Legal and ethical.** Testing is limited to systems you own or have written
    permission to assess. When in doubt, stop and ask the owner in writing.

## Wave order for the 14 cards

| Wave | Cards | Why first |
|---|---|---|
| 1 | VIBE-01, VIBE-02, VIBE-13 | Anonymous and cross-identity reads are cheapest and highest signal |
| 1 | VIBE-12 | Two requests expose cache keying |
| 2 | VIBE-03, VIBE-05, VIBE-06 | Authorization and UI-only gates |
| 2 | VIBE-04, VIBE-09, VIBE-10 | Token, redirect and rendering checks |
| 3 | VIBE-07, VIBE-08, VIBE-11, VIBE-14 | Races, validation, SSRF and model trust |

A card moves earlier only when the threat model names its asset as critical. Brute
and multi-step tests stay in reserve until the cheaper wave is complete.
