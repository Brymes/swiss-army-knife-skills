# nip.io, sslip.io and dash notation

`nip.io` and `sslip.io` are wildcard DNS services. They encode an address in a
hostname and return that address in an A or AAAA record. A validator that only
blocks the literal strings `127.0.0.1` or `localhost` can therefore be bypassed by
a name that resolves to loopback.

This note supports `SSRF-03` and `VIBE-11`. It is reference material for
authorized testing only; it is not a list of live targets.

## How the mapping works

A hostname of the form `<address>.<service>` resolves to `<address>`.

| Hostname | Resolves to |
|---|---|
| `127.0.0.1.nip.io` | `127.0.0.1` |
| `127-0-0-1.nip.io` | `127.0.0.1` |
| `10-0-0-1.nip.io` | `10.0.0.1` |
| `192-168-1-1.sslip.io` | `192.168.1.1` |
| `0x7f000001.nip.io` | `127.0.0.1` where the resolver accepts hex labels |
| `127.0.0.1.sslip.io` | `127.0.0.1` |

The dash form is the portable one: dots inside a hostname label are also legal in
some resolvers, but a dash form avoids ambiguity between the embedded address and
the service suffix. For IPv6, the provider's documented form uses dashes between
hex groups; treat it as provider-specific and verify offline before use.

## Why it defeats naive checks

A substring blocklist such as:

```python
if "127.0.0.1" in url or "localhost" in url:
    return deny()
```

does not match `127-0-0-1.nip.io`. The fetcher's HTTP client resolves the name,
connects to `127.0.0.1`, and sends a Host header of `127-0-0-1.nip.io`. The
internal service receives a request it never expected from the public path.

The same gap appears in suffix checks that trust any name ending in an allowed
domain, in validators that resolve once and connect later, and in blocklists that
do not re-check redirect hops.

## Safe test procedure

1. Confirm the mapping offline with the resolver on the test host. Record the
   answer and TTL.
2. Use the authorized local fixture's own loopback endpoint as the only internal
   destination. Do not point at a real metadata service, an internal network range
   or a third-party host.
3. Ask the fetcher for the dash-form name and compare with the blocked literal
   control.
4. Stop at the first internal response. Do not scan ports or enumerate hosts.
5. Redact any token returned by the internal endpoint.

Example against the local fixture (authorized loopback only):

```text
POST /api/fetch
{"url": "http://127-0-0-1.nip.io:8765/internal/metadata"}
```

A correct defense resolves the hostname, rejects loopback, link-local, private and
metadata addresses, pins the resolved address for the connection, re-validates
every redirect hop and refuses non-HTTP schemes. Blocking the literal string is
not a defense.

## Relationship to DNS rebinding

`nip.io` is a static wildcard mapping; DNS rebinding changes the answer between
the validation lookup and the connection. `SSRF-07` covers rebinding and requires
a local simulation. Do not use a live public rebinding service against a target
you do not own.

## Evidence to keep

- The hostname and the resolver answer with timestamp.
- The fetch request and the minimum internal response excerpt.
- The blocked literal control.
- The validator implementation or a note that it is substring-only.
- The redaction note for any token or internal path.

No payload in this pack points at a live external host. Every payload is active
and authorized-target-only; see `payloads.yaml`.
