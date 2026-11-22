# Scope — Playwright adapter fixture run

Authorized fixture only: the localhost vulnerable app. No external host is listed, so the
allowlist stays default deny everywhere else.

## Allowed hosts
- localhost:8765
- 127.0.0.1:8765

## Budget
- max_requests: 200
- max_seconds: 120
