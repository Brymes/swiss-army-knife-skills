# Safety and limits

Security work is dual-use. The difference between an assessment and an attack is
authorization plus restraint, both written down and both enforced before the
first request.

## Authorization

- **Written scope is the only authorization.** A chat request, a public URL or a
  "it's my company's app" claim is not enough. Get hosts, paths, methods,
  accounts and a window in `scope.md`, with an authorizer and a date.
- **Program policy counts as written scope** for a bug-bounty target, but only
  within the program's rules and only on its listed assets. Paste the rules; do
  not paraphrase them into something wider.
- **Default deny.** If an asset is not listed, it is out of scope. DNS
  neighbours, shared CDNs, auth providers, payment processors, cloud metadata
  endpoints and upstream APIs are out unless explicitly listed.
- **One target, one scope.** Do not reuse a scope file across engagements or
  carry a host forward because it appeared in an old scan.
- **Right to stop.** The target owner can pause or end the engagement at any
  time. Record it, stop traffic and preserve logs.

Adapters enforce a narrower version of this: an active adapter refuses without a
scope entry for the host. The refusal is a feature. Do not patch around it,
change the host header, or point the tool at an IP literal to bypass the check.

## Forbidden actions

These are never part of the default workflow, even on an authorized target,
unless the written scope explicitly names them and the owner approves in
writing:

- destructive writes, deletes, truncation, schema changes or data corruption;
- denial of service, load testing, resource exhaustion, fork bombs, zip bombs,
  billion-laughs, regex DoS or unbounded fuzzing;
- persistence: shells, cron jobs, SSH keys, new admin accounts, webhooks that
  survive the engagement;
- credential attacks: password spraying, credential stuffing, session fixation
  against real users, phishing, social engineering;
- exfiltration or retention of real user data, secrets, tokens, private keys or
  production database dumps;
- lateral movement to hosts outside scope, including cloud instance metadata and
  internal services reachable from the target;
- third-party exploitation: a dependency's SaaS, a payment provider, a shared
  identity provider;
- evasion for its own sake: WAF bypass is in scope only when the question is
  "does the control hold?", not "can I hide?".

Brute-intensity cards and `sqlmap`-class tools are reserve actions: one at a
time, rate-limited, approved, and stopped at the first sign of instability.

## Secrets and data

- **Never print secrets.** That includes cookies, bearer tokens, API keys,
  passwords, session IDs, private keys, `Authorization` headers, connection
  strings and personal data.
- **Redact at capture time.** Write the redacted request/response or other
  mode capture to `evidence/`; keep the raw secret only in the environment or a
  secret manager, never in a file, log, prompt or report.
- **Mask in commands.** Prefer environment variables over command-line
  arguments, because process lists leak. When a command is logged, replace the
  value with `<redacted>`.
- **Minimum necessary data.** Capture the fields that prove the claim, not the
  whole table. If a response contains other users' data, record only enough to
  show the boundary was crossed and then stop.
- **Model context is a data sink.** Prompt hunters must not receive raw secrets,
  full production records or third-party personal data. Summarize or redact
  before the prompt.
- **Dispose on schedule.** Agree an evidence retention period in `scope.md` and
  delete the run directory when the engagement closes, unless the owner needs
  it for disclosure.
- **No secrets in git.** `.env` is ignored. Do not commit captures, keys or
  provider payloads; `vendor/external/` is ignored for the same reason.

## Rate and blast radius

- Start at one request per second per host, one connection, no retries beyond
  two. Raise it only when the scope allows and the target is stable.
- Concurrency is for read-only hunters and separate accounts. Cap it (three is
  a sane default), and never let two hunters mutate the same resource.
- Respect `Retry-After`, `429` and `503`. A rate limit is a stop signal, not a
  challenge.
- Stop on the first unexpected effect: a 5xx spike, a restart, a queue backlog,
  another user's data in a response, a write you did not intend.
- Prefer a test account and a staging copy. If only production exists, reduce
  to passive review and ask before any active test.
- Keep the local fixture local. Tests and demos use `127.0.0.1`; no live
  external target is part of the test suite.
- Optional engines run in their own environment. Do not point an engine's
  autonomous loop at a host you have not scoped, and do not let it install
  global tools.

## Tool and license limits

- Do not vendor GPL, AGPL or unlicensed code. Blackbird, T3MP3ST, PentAGI and
  ARTEX stay external under `vendor/external/` and are gitignored; they are used
  through their documented checkout or engine commands.
- MIT-licensed skills may be vendored with provenance; read `vendor/PROVENANCE.md`
  and keep the upstream notice.
- A tool's license does not grant authorization to a target. Both are required.
- OSINT tools (Blackbird, Webseek) touch third-party data. Use them only for
  in-scope identifiers, bound the request count, and treat results as leads that
  need verification, not as findings.

## Stop rules

Stop immediately and write the blocker into `state.json` and
`NEEDS-VALIDATION.md` when:

- the target or account is not in `scope.md`;
- a request would cross a forbidden-action line;
- you see real user data, a secret or another tenant's record;
- the target becomes unstable or the owner asks to pause;
- a tool wants to install globally, escalate privileges or persist;
- the budget is exhausted or two waves add no signal;
- the verifier cannot reproduce a claim and no cheaper test remains.

Stopping is a successful outcome when the alternative is an out-of-scope action.
Preserve the logs, record the next action and hand back to the human owner.

Next: the hunting loop in [prompt-mutation.md](prompt-mutation.md).
