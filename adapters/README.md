# Adapters

Adapters turn one planned step into a bounded, auditable command plus normalized
candidate findings. They are plain Python modules loaded by path from `src/sak/run.py`;
nothing here is installed globally, vendored from a third party, or imported by the
catalog loader.

## Rules every adapter follows

1. **No assumed authorization.** An adapter never decides that a target is in scope.
   `sak run --execute` checks `scope.md`, the plan, the step's real destination and the
   budgets *before* an adapter is allowed to run. A dry run may print the command without a
   scope file, because a dry run never touches the network.
2. **Offline by default.** `check()` only inspects the host: it resolves a binary, reads a
   version string, looks for an external checkout or an environment variable. It never
   downloads templates, clones a repository, installs a package or contacts a target.
   `execute()` is only reachable through `sak run --execute`.
3. **Only authorizable destinations execute.** An adapter declares `DESTINATION_POLICY`:
   `target` means it talks to the plan target and the `scope.md` gate is meaningful;
   `external` or `provider` means the real destinations are chosen elsewhere and cannot be
   authorized by `scope.md`, so the runner refuses execute and keeps the dry run.
4. **No destructive defaults.** No denial-of-service, brute-force or destructive payload
   flags are generated. Nuclei runs with `-no-interactsh` unless the step opts in
   explicitly, no template path may be remote, and no adapter enables headless, fuzzing or
   OAST callbacks by default.
5. **Everything returned or written is sanitized.** `run.py` masks secret environment
   values and auth-shaped strings in command arrays, display text, findings, usage,
   parse errors and logs. Tool captures are parsed from stdout or a temporary file and are
   never retained under the run directory.
6. **Candidate findings only.** Parsers emit records with `status: needs_validation`.
   An adapter never claims a finding is `confirmed`; verification is a later phase.

## Module interface

Each file in this directory is standalone (no cross-adapter imports) and exposes:

| Name | Kind | Contract |
|---|---|---|
| `ADAPTER_ID` | `str` | Catalog id of the card, e.g. `nuclei`. |
| `NAME` | `str` | Human label. |
| `REQUIRES` | `tuple[str, ...]` | Runtime requirements, reported when missing. |
| `DESTINATION_POLICY` | `str` | `target`, `external` or `provider`. Only `target` may execute. |
| `DESTINATION_REFUSAL` | `str` | Operator-facing reason used when the policy blocks execute. |
| `LICENSE_NOTICE` | `str` | Third-party license/terms notice, including "do not vendor" guidance. |
| `check()` | function | `{"adapter", "available", "binary", "version", "missing", "hints", "notes", ...}`. Host inspection only. |
| `build(step, target, *, run_dir=None)` | function | `{"command", "display", "notes", "requires_scope"}`. Builds a dry-run command. Raises `ValueError` for invalid or non-local step options. |
| `estimate_requests(step, seconds=60)` | function | Conservative integer estimate for a run of *seconds*. Return `0` when no truthful bound exists. |
| `execute(step, target, *, binary=None, timeout=300, run_dir=None)` | function | Runs the command and returns `{"command", "returncode", "stdout", "stderr", "findings", "usage", ...}`. Returns `{"refused": True, "reason": ...}` instead of raising when a runtime requirement is absent. |
| `parse(text)` | function | Normalizes raw tool output into candidate finding records. |

A **step** is the plan candidate dict (`id`, `name`, `role`, `adapter`, ...) plus an
optional `options` mapping:

```yaml
# excerpt of a step inside plan.json
id: nuclei
adapter: nuclei
options:
  severity: high,critical
  rate_limit: 5
  timeout: 10
  retries: 1
  templates: /opt/nuclei-templates/http  # must be an existing local path
```

Normalized finding record (all adapters):

```json
{
  "id": "nuclei:fixture-sqli",
  "title": "Fixture SQL injection",
  "severity": "high",
  "status": "needs_validation",
  "source": "nuclei",
  "target": "http://localhost:8765/search?q=1",
  "evidence": {"template": "fixture-sqli", "matcher": "error"}
}
```

## Destination policy

| Adapter | Policy | Execute | Why |
|---|---|---|---|
| Nuclei | `target` | Allowed after the scope and budget gates | It requests the plan target, and template paths must already exist locally. |
| Blackbird | `external` | Refused | Its external site list, not the plan target, decides the destinations, and it exposes no truthful request bound. |
| Webseek | `provider` | Refused | The provider endpoint is chosen by the CLI/configuration and every query is billed; `scope.md` cannot authorize it. |

Dry runs, parsers and usage extraction stay available for the refused adapters; run those
tools manually under separate authorization. Do not treat a smaller user-supplied site or
result count as a bound when the tool still contacts its full list.

## Run directory layout

`sak run --execute` writes only sanitized artifacts inside the run directory:

```
runs/<run-id>/
  scope.md                 # authorization allowlist, supplied by the operator
  plan.json                # written by `sak plan --run-dir`
  budget.json              # request/time spend accumulated across steps
  logs/<step>.log          # masked command, stdout and stderr
  steps/<step>.json        # sanitized adapter result (command, returncode, usage, policy)
  findings/<step>.json     # sanitized candidate findings
```

No raw Nuclei JSONL, Blackbird CSV or provider payload is written to the run directory: the
adapter parses stdout (Nuclei, Webseek) or a temporary CSV that is deleted after parsing
(Blackbird).

## `scope.md` format

Default deny. Only an explicit positive heading can authorize a host, and only its host
bullets or the Asset column of its Markdown table are read. The reviewed scope template's
`## In scope` table is supported: `/path`, `repo@revision` and `source`/`binary` asset rows
are ignored because the host gate cannot enforce them, while `web`, `api` and `fixture`
rows must name a valid host.

- **Positive:** `Allowed hosts`, `Allowed targets`, `Allowlist`, `In scope`, `Authorized
  hosts`, `Scope`, `Targets`, `Hosts`.
- **Negative:** `Out of scope`, `Exclusions`, `Excluded hosts`, `Deny`, `Forbidden`, `Do not
  test`, `Not allowed`. These deny; they never authorize. Prose bullets are ignored.
- **Ignored:** notes, methodology, forbidden-action prose, accounts tables and any unknown
  heading. A host mentioned there is not authorized.

```markdown
# Scope — run 20261115T1200-web-blackbox

## In scope

| Asset | Type | Allowed methods / actions | Notes |
|---|---|---|---|
| https://localhost:8765 | web | GET, HEAD, POST | local fixture |
| 127.0.0.1:8765 | fixture | all fixture routes | local lab only |
| github.com/org/repo@<sha> | source | read-only clone | not a host destination |

## Out of scope
- 127.0.0.2:8765

## Budget
- max_requests: 500
- max_seconds: 300
```

Entry syntax is strict: `host`, `host:port`, `scheme://host[:port]` with `http`/`https`
only, or a bracketed IPv6 literal. Wildcards, CIDR ranges, userinfo, query strings,
unbracketed IPv6 and out-of-range ports are rejected. Any rejected host entry is recorded in
`scope.errors` and makes `--execute` refuse entirely instead of guessing. Budget bullets are
only accepted under a budget heading, and a bullet that is not a `key: number` budget entry
is ignored as prose; a bare host entry (`staging.example.test`) allows any port on that host,
while `host:port` allows exactly that port.

## Third-party handling

| Adapter | Upstream | License / terms | How sak treats it |
|---|---|---|---|
| Nuclei | projectdiscovery/nuclei | MIT | Installed by the operator; never vendored. Templates must be local existing paths. |
| Blackbird | p1ngul1n0/blackbird | GPL-3.0, with CC BY-NC-SA terms on its bundled site data | **External only**, expected under gitignored `vendor/external/blackbird`; sak prints checkout/venv instructions and never clones or vendors it. Execute is refused. |
| Webseek | external research CLI/MCP | Upstream license and provider API terms apply | Reached through `npx`; never vendored, no key required for a dry run, execute refused. |
