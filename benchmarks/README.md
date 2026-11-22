# Benchmark records

This directory holds durable, secret-free summaries of the skill benchmark. Each
record is derived from a live loopback run whose raw evidence stays under the
gitignored `runs/` directory.

| File | Target | Rubric | Confirmed | Coverage |
|---|---|---|---|---|
| `vuln-bank.json` | vuln-bank | 15 | 15 | 15/15 |
| `dvwa-low.json` | DVWA Low | 11 | 11 | 11/11 |

Read [docs/benchmark.md](../docs/benchmark.md) for the method, interpretation and
reproduction commands. Read [docs/skill-usage.md](../docs/skill-usage.md) for how
the installed OpenCode skill drives the run.

## Record shape

```json
{
  "schema": "sak.skill.benchmark.v1",
  "benchmark": "dummy-target-rubric-v1",
  "date": "YYYY-MM-DD",
  "target": "vuln-bank",
  "target_url": "http://127.0.0.1:15000",
  "profile": "targets/vuln-bank/blackbox/profile.yaml",
  "run_dir": "runs/blackbox-vuln-bank-final",
  "environment": "loopback lab",
  "rubric": {
    "expected": 15,
    "confirmed": 15,
    "needs_validation": 0,
    "rejected": 0,
    "coverage": {"covered": 15, "partial": 0, "missed": 0, "deferred": 0, "ratio": 1.0}
  },
  "checks": {"confirmed_artifacts": 16, "needs_validation_artifacts": 0, "rejected_artifacts": 0, "requests": 457},
  "findings": [
    {
      "id": "F-VB-AUTH-01",
      "issue": "VB-AUTH-01",
      "title": "SQL injection in login",
      "class": "authentication",
      "severity": "critical",
      "status": "confirmed",
      "entrypoint": "/login",
      "check": "VB-AUTH-01",
      "artifact": "exploit/VB-AUTH-01.json",
      "evidence_sha256": "..."
    }
  ],
  "hunt": {"run_dir": "...", "prompts": ["..."], "candidates": 1, "errors": 1, "note": "..."},
  "caveats": ["..."],
  "commands": ["..."]
}
```

Rules:

- `rubric.expected` is the profile's `expected` list length; it is the denominator.
- `rubric.confirmed` is the number of expected issues with a verified proof.
- `checks.confirmed_artifacts` may be larger than `rubric.confirmed` when a
  denial check maps to the same issue.
- Every `findings[].status` is `confirmed`; candidates belong in `hunt`.
- `target_url` is loopback. No tokens, cookies, passwords, keys or card data are
  stored.
- A benchmark is clean only when `sak verify` reports no unknown ids, extras or
  ambiguous records and `sak report` renders the same confirmed count.

## Reproduce

```sh
uv run sak exploit --run runs/blackbox-vuln-bank-final \
  --target http://127.0.0.1:15000 \
  --profile targets/vuln-bank/blackbox/profile.yaml --json
uv run sak verify --run runs/blackbox-vuln-bank-final \
  --profile targets/vuln-bank/blackbox/profile.yaml --json
uv run sak report runs/blackbox-vuln-bank-final
```

Use `http://127.0.0.1:5000` on Kali for vuln-bank. DVWA uses
`http://127.0.0.1:8080`. The full command matrix, setup and cleanup notes are in
[docs/blackbox-pilot.md](../docs/blackbox-pilot.md).
