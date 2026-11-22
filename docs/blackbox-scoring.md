# Black-box verification and scoring

`sak verify` turns a run's raw records into a scoped verdict: it scores every
expected issue in a target profile's rubric, states how much of that rubric was
covered, and keeps the difference between "all intended issues" and "all possible
issues" explicit. It is offline and read-only with respect to the source run.

```sh
uv run sak verify --run runs/<run> --profile targets/dvwa/blackbox/profile.yaml
uv run sak verify --run runs/<run> --profile targets/dvwa/blackbox/profile.yaml --json
```

Exit code `0` means the verification documents were written, including runs with
gaps. Exit code `1` is an input error: a missing run directory or profile, an
unreadable JSON record, or a rubric with duplicate ids.

## 1. Inputs

| Input | Required | Used for |
|---|---|---|
| `--run DIR` | yes | The run directory; source evidence is never modified. |
| `--profile PATH` | yes | The `expected` rubric that defines the denominator. |
| `findings.json` | no | Triage records and their evidence hashes. |
| `exploit/*.json` | no | Profile-driven checks with a proof flag and embedded evidence. |
| `hunt/*.json` | no | Bounded hunter records and their candidate lists. |

The profile is the `sak.blackbox.profile.v1` contract documented in
[`blackbox-targets.md`](blackbox-targets.md). Only the `expected` list and the
`target.id`/`target.name` labels are read by the verifier.

## 2. Outputs

`sak verify` writes three derived files next to the source evidence:

| File | Purpose |
|---|---|
| `verify.json` | Machine-readable rubric table, counts, evidence hashes, gaps, extras, unknown ids and the scoped statement. |
| `VERIFICATION.md` | Reviewer-facing report with the same data and the proof/coverage rules. |
| `verified-findings.json` | Source findings annotated with `rubric:<ID>` (or `rubric:extra`) and the verified status. |

`findings.json`, `exploit/*.json`, `hunt/*.json` and every evidence file stay
byte-identical. The derived findings document drops evidence entries whose file
is missing or whose hash no longer matches, so it can be validated on its own;
the original record remains untouched in `findings.json`.

## 3. Rubric contract

The `expected` list is the coverage denominator. Each entry should carry a
stable id, a title, a class and an endpoint; severity, proof, cleanup, intrusive
and default flags are optional but recommended.

```yaml
expected:
  - id: DVWA-SQLI-01          # stable, unique; the join key for every record
    title: SQL injection exposes credentials and data
    class: sql-injection      # semantic class used for non-explicit matching
    endpoint: /vulnerabilities/sqli/?id=1&Submit=Submit
    proof: A UNION payload returns rows from the users table.
    severity: high
    default: true             # false => deferred when no record is mapped
```

Rules:

- **Ids are unique.** A duplicate id is a hard error; one id must mean one issue.
- **Ids are stable** across runs so evidence and reports can be compared.
- **`default: false`** (or `deferred: true` / `excluded: true`) marks an issue
  that is intentionally not attempted. With no mapped record it becomes
  `deferred` rather than `missed`.
- **`proof` is the contract for `confirmed`.** The checker must observe it, not
  infer it.

## 4. Mapping evidence to rubric ids

Mapping is deterministic and first-match wins:

1. **Explicit id.** An exploit check whose `check` equals the rubric id, a
   finding tag equal to the id or `rubric:<ID>`, `source.prompt` equal to the
   id, or a record field `issue`/`expected`/`rubric_id` equal to the id.
2. **Unique semantic match.** The record's endpoint path (query stripped,
   trailing slash removed) equals the rubric `endpoint` path **and** its
   root-cause/class slug equals the rubric `class`. Slugs are compared after
   lower-casing and folding `-`, `_` and spaces to `-`.
3. **Exploit action class.** When a check has no explicit id, its action maps to
   a class (for example `sql_injection` -> `sql-injection`) and matches only when
   exactly one rubric entry has that class.

A record that matches more than one rubric entry is listed under `ambiguous` and
counted in `extras`; it is never double counted. A record that matches none is an
extra. Explicit ids not present in the rubric are listed in `unknown_ids`. Extras
and unknown ids are visible but never expand the denominator.

Candidates from `sak hunt` are always `needs_validation`: a hunter reports what
it observed as a candidate, not a proof.

## 5. Verdicts and proof rules

| Verdict | Meaning | Required observation |
|---|---|---|
| `confirmed` | The issue was proven. | An exploit check with `proof: true` and embedded evidence, or a finding with `status: confirmed` and at least one readable evidence file whose SHA-256 matches. |
| `needs_validation` | A candidate or partial observation. | A hunter candidate, an unsupported/deferred check, a `needs_validation` finding, or a `confirmed` record that failed the proof check. |
| `rejected` | The attempt ran and disproved the proof condition. | An exploit/finding record with `status: rejected` and its reason. |
| `none` | No record mapped to the rubric id. | Nothing. |

Never promoted without evidence:

- A `confirmed` finding with no readable evidence is downgraded to
  `needs_validation` and the reason is recorded.
- A `confirmed` exploit check without `proof: true` or without embedded evidence
  is downgraded the same way.
- A missing evidence file or a hash mismatch invalidates that evidence record.
- Source statuses are never changed in place; only the derived
  `verified-findings.json` carries the verified status.

When several records map to one issue, the strongest verdict wins:
`confirmed` > `needs_validation` > `rejected` > `none`. The records are all kept
in the issue's `records` and `evidence` lists.

## 6. Coverage semantics

Coverage answers "how much of the rubric reached a clean proof?", not "how many
requests ran?".

| Coverage | Condition |
|---|---|
| `covered` | The issue is `confirmed`. |
| `partial` | The issue is `needs_validation` with mapped evidence or a mapped record. |
| `missed` | The issue is `rejected`, or no record mapped and the issue was not deferred. |
| `deferred` | No record mapped and the rubric entry is disabled by default or excluded. |

`ratio = covered / expected` (rounded only by JSON's float representation).
`rejected` is `missed` because a disproved issue is not a clean proof; the
verdict column still distinguishes "tested and disproved" from "never tested".
`unattempted` counts issues with no mapped record at all.

The counts add up:

```text
expected = confirmed + needs_validation + rejected + none
expected = covered + partial + missed + deferred
```

## 7. "All intended issues" versus "all possible issues"

`VERIFICATION.md` always carries both statements:

- **All intended issues:** every id in the profile rubric was scored, with the
  confirmed/partial/missed/deferred split.
- **All possible issues:** the denominator is the rubric, not the universe of
  defects. Records outside the rubric are extras. A fully covered rubric means
  "the intended list was evidenced", not "the application has no other bugs".

This is why the DVWA Low rubric has 11 ids and the vuln-bank rubric has 15: a
report claiming those counts is making a scoped claim about the profile, and the
document says so.

## 8. Evidence hashes

Every mapped artifact is hashed with SHA-256 and listed in `verify.json`
(`hashes`) and `VERIFICATION.md`. Finding evidence is resolved relative to the run
directory; exploit and hunt artifacts are hashed as stored. A reviewer can re-run
the hashes and confirm the report still describes the same bytes. Hash mismatches
and missing files appear in the issue notes and gaps.

## 9. Extending a target profile

1. Add one `expected` entry with a new stable id, `class`, `endpoint`, `proof`,
   `severity` and `default` flag. Do not reuse an id.
2. Add or point an exploit check at the same id (`exploit.checks[].id`), or tag
   the finding with `rubric:<ID>`. Explicit ids are the most reliable mapping.
3. Keep the proof condition observable in one bounded check. If the check cannot
   prove it yet, leave it `needs_validation`; do not mark it confirmed.
4. Add the class to the semantic matcher only if it is unambiguous. Otherwise
   rely on explicit ids so two issues cannot match one record.
5. Add an offline fixture case for the new verdict/coverage path and run:

   ```sh
   uv run pytest tests/test_verify.py -q
   uv run sak verify --run runs/verify-test \
     --profile tests/fixtures/verify/profile.yaml --json
   ```

6. Keep `checks.json`, the profile rubric and the docs in step: one issue id
   should map to one check and one proof condition.

## 10. Offline fixture

`tests/test_verify.py` builds a synthetic run under `tests/fixtures/verify/` and
`runs/verify-test/` with five rubric ids covering confirmed, partial, missed,
deferred, missing-evidence, duplicate-id, unknown-id, extra and empty-run paths.
No live target or network is used. The fixture is regenerated by the test module
because the task's write scope covers `tests/test_verify.py`, not
`tests/fixtures/verify/`.
