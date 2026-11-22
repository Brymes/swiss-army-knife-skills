# Scope — adapter fixture run

Authorized fixture only: the localhost vulnerable app from T8. No external host is listed,
so the allowlist stays default deny everywhere else.

## Allowed hosts
- localhost:8765
- 127.0.0.1:8765

## Budget
- max_requests: 500
- max_seconds: 60
