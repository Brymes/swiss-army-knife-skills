# Scope — vuln-bank (example)

Copy of the authorization envelope for the local vuln-bank lab. `sak run --execute` is
default deny: only hosts listed under a positive heading below are reachable, and only
these loopback endpoints. Do not add external hosts.

## Allowed hosts
- 127.0.0.1:5000
- localhost:5000

## Out of scope
- Any non-loopback host
- The upstream project's public demo or any internet-facing deployment
- Host port 5432 (Postgres); the harness never talks to it directly

## Budget
- max_requests: 500
- max_seconds: 900

## Rules of engagement
- Authorized lab only: loopback Docker on the assessment host, or the same lab reached
  through the owner's Legion/VPN tunnel.
- Two lab users are enough for BOLA/BOPLA checks; do not touch real data.
- No brute force, denial of service or destructive writes. The 3-digit PIN scenario stays
  disabled unless the owner opens it here and records the request cap.
- Writes are serialized and one of the following must be recorded before each write:
  the account pair, the object id and the expected state change.
- Stored-XSS payloads are benign (`alert(document.domain)`) and cleaned by the lab's
  `xss-cleaner` within 15 minutes; do not use payloads that persist beyond the window.
- Stop on scope or account mismatch, an unapproved write, or two waves without new signal.
