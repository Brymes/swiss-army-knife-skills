# Threat model — local authorized fixture

Target: `http://127.0.0.1:8765` (local fixture only; no external hosts).

## Assets

- User account records: profile, email, role, credits and AI usage.
- Password-reset tokens and active sessions.
- Admin actions and the hidden cache-purge route.
- AI completion quota and the model context window.
- Server-side fetch capability and the internal metadata endpoint.
- Rendered profile HTML and preview pages.

## Trust boundaries

- Anonymous client to the public API.
- Authenticated user to another user's object.
- Browser rendering to stored profile HTML.
- API server to the server-side fetch destination.
- User message to the model context and retrieval corpus.
- Public cache to a personalized dashboard response.

## Invariants

- Every object read, edit and delete checks ownership or role on the server.
- Security-relevant fields are derived from server state, never mass-assigned.
- A reset token is single-use and is never disclosed to the requester.
- Quotas and credits are enforced atomically by the API, not only by the page.
- A URL fetch cannot reach loopback, metadata or a non-HTTP scheme.
- A personalized response is never served from a shared cache key.
- Model output and retrieved documents cannot grant access to another identity's data.
