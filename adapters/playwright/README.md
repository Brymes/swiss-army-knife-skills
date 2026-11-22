# Playwright adapter

`adapters/playwright.py` drives a JSON scenario through `adapters/playwright/runner.mjs`, a
small Node script that uses the Playwright API. The adapter is a **browser check**: it records
what a browser actually did. A candidate it returns is `needs_validation` evidence, not a
confirmed finding.

The adapter never imports Playwright, installs packages, downloads browsers or starts Node on a
dry run. `check()` only looks at the host and the browser cache.

## Prerequisites (operator actions, never run by sak)

```sh
npm install --global playwright
npx playwright install chromium
```

Node.js must be on `PATH` (npx ships with it). Browsers live in the Playwright cache
(`~/Library/Caches/ms-playwright` on macOS, `~/.cache/ms-playwright` on Linux) and are never
committed. `SAK_PLAYWRIGHT_BROWSERS_PATH` and `PLAYWRIGHT_BROWSERS_PATH` are honoured when the
cache lives elsewhere; the first is also what the offline tests use.

The runner imports `playwright` from `adapters/playwright/`, so the package must be resolvable
from that directory: install it in a project that contains this checkout, or export
`NODE_PATH` to the global `node_modules`. A global install alone is not importable by Node
unless `NODE_PATH` points at it. `check()` probes this import and reports a missing package as
`playwright module`.

## Adapter interface

| Name | Value |
|---|---|
| `ADAPTER_ID` | `playwright` |
| `DESTINATION_POLICY` | `target` (`scope.md` must name the host; the runner refuses other origins) |
| `LICENSE_NOTICE` | Playwright is Apache-2.0; package and browsers are operator-installed |
| `check()` | reports Node, npx, the playwright module, the runner and cached Chromium presence plus install hints |
| `build()` | validates the scenario and prints the runner command; launches nothing |
| `execute()` | refuses without Node, npx, the module, the runner or Chromium, then runs the scenario once |
| `parse()` | turns runner observations into `needs_validation` candidate records |
| `estimate_requests()` | one page load plus one exchange per network-capable action |

Step options:

| Option | Default | Meaning |
|---|---|---|
| `scenario` | none (required) | path to the scenario JSON, relative to the run directory |
| `timeout_seconds` | `60` | per-run bound passed to the runner |
| `browser` | `chromium` | Playwright browser type |
| `headed` | `false` | run with a visible browser |

## Scenario JSON

```json
{
  "name": "login-check",
  "viewport": {"width": 1280, "height": 800},
  "steps": [
    {"action": "goto", "url": "/login"},
    {"action": "fill", "selector": "#username", "value": "${APP_USER}"},
    {"action": "fill", "selector": "#password", "value": "${APP_PASSWORD}"},
    {"action": "click", "selector": "button[type=submit]"},
    {"action": "expect_url", "contains": "/account"},
    {"action": "expect_text", "selector": "#welcome", "text": "Welcome"},
    {"action": "expect_status", "status": 200},
    {"action": "wait_for", "selector": "#logout"},
    {"action": "screenshot", "path": "after-login.png"},
    {"action": "save_storage_state", "path": "storage.json"}
  ]
}
```

Supported actions:

| Action | Required fields | Notes |
|---|---|---|
| `goto` | `url` | absolute URL or a path resolved against the current page; same origin only |
| `fill` | `selector`, `value` | the typed value is never recorded in the result |
| `click` | `selector` | |
| `select` | `selector`, `value` | |
| `expect_url` | `url`, plus `contains` or `pattern` to relax the match | exact match otherwise |
| `expect_text` | `text` or `pattern`; optional `selector` | records up to 2000 characters of selected text |
| `expect_status` | `status` or `equals` | compares the last navigation status |
| `wait_for` | `selector`, `text` or `timeout_ms` | |
| `screenshot` | optional `path`, `full_page` | default `step-<n>.png` under the artifacts directory |
| `save_storage_state` | `path` | written with mode `0600`; it contains cookie values |

The runner opens the plan target once before the steps, so a scenario can begin with
`expect_text` or `wait_for` instead of `goto`. Relative `goto` URLs resolve against the
current page, and any navigation that leaves the target's origin fails that step instead of
following it.

## Environment substitution

Any `${NAME}` inside a scenario string is replaced from the process environment at execute
time. Put credentials in the environment, never in the scenario file:

```sh
export APP_USER=fixture-user
export APP_PASSWORD='...'   # operator shell only; never commit
uv run sak run --run runs/example --step playwright --execute
```

A missing variable fails the run before the browser starts. The result document lists only
the variable *names* it used (`env_names`), and every substituted value is replaced with
`***` in recorded text, URLs and console messages. `node runner.mjs --scenario file.json
--check` validates a scenario and reports required names without launching a browser.

## Result document

`execute()` writes `<run-dir>/logs/playwright-result.json` (mode `0600`) and returns the
parsed candidates:

```json
{
  "schema_version": "1",
  "target": "http://127.0.0.1:8765",
  "initial": {"url": "...", "title": "...", "status": 200},
  "steps": [
    {"index": 1, "action": "expect_text", "status": "failed", "url": "...",
     "title": "...", "status_code": 200, "selected_text": "Login", "error": "..."}
  ],
  "cookies": [{"name": "PHPSESSID", "domain": "...", "path": "/", "http_only": true,
               "secure": false, "same_site": "Lax", "expires": -1}],
  "console_errors": [{"step": 4, "type": "console", "text": "..."}],
  "observations": [{"kind": "expectation_failed", "severity": "medium", "step": 2,
                    "title": "Expectation failed: expect_text", "expected": "...",
                    "observed": "..."}],
  "env_names": ["APP_USER", "APP_PASSWORD"],
  "ok": false
}
```

Cookies are recorded as **names and flags only**. `save_storage_state` writes the operator's
requested path with mode `0600`; that file does contain cookie values and must stay out of git.
Screenshots and storage-state files go under `<run-dir>/artifacts/playwright/` by default.

## Candidate output shape

`parse()` turns each observation into the same candidate shape every sak adapter emits:

```json
{
  "id": "playwright:1:expectation_failed:expectation-failed-expect-text",
  "title": "Expectation failed: expect_text",
  "severity": "medium",
  "status": "needs_validation",
  "source": "playwright",
  "target": "http://127.0.0.1:8765/account",
  "evidence": {"kind": "expectation_failed", "step": 2, "action": "expect_text",
               "expected": "...", "observed": "...", "detail": "..."}
}
```

Observations come from failed `expect_*` steps, HTTP error responses on `goto`, and console
errors. Cookie metadata and step logs stay in the result document as evidence; they do not
become candidates.

## Browser check vs confirmed finding

A browser check shows that a browser was redirected, saw a status, rendered text, or raised a
console error. That is evidence, not proof of a vulnerability. A candidate starts as
`needs_validation` and needs an operator to confirm impact (for example, that the redirect is
an authentication bypass and not a normal login flow), attach the screenshot or storage-state
path as evidence, and then move it to `confirmed` through `sak findings status`. The adapter
never writes `confirmed` or `rejected` itself.

## Safety

- The scenario file and the `scope.md` allowlist are separate gates: sak refuses to execute
  when the plan target is not in `scope.md`, and the runner refuses to navigate off the
  target's origin.
- No proxy, download, upload or OAST action exists. Do not add one without an owner decision.
- Results, screenshots and storage state stay under the run directory. Never commit them;
  mask or delete storage state once the evidence is attached.
