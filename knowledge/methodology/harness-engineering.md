# Harness engineering for vulnerability research — reading notes

**Source:** *Introduction To Harness Engineering For Vulnerability Research*, by
[Graham Helton](https://grahamhelton.com/) and [Ryan Basden](https://ryanbasden.com/).
Book: <https://grahamhelton.github.io/harness-engineering-workshop-book/print.html>.
Retrieved 2026-11-11. This is a summary in our own words for internal use, not a copy of
the book and not a substitute for reading it. The book is a workshop text; its examples
are teaching material, not a benchmark of any product.

## What the book argues

Model capability is not research capability. A strong model can still produce weak
vulnerability research when it lacks target context, deterministic tools, authorization
boundaries, durable state and a validation method. The workshop therefore builds a
target-specific **harness** around an ordinary agent instead of shipping a scanner or a
ready-made research scaffold.

The intended outcome is deliberately modest: a working harness, evidence about **one**
tested hypothesis, and a repeatable method for continuing. A vulnerability is not a
promised result. Agent output is a lead, never a finding; the human remains responsible
for authorization, security judgment, runtime validation, impact analysis and disclosure.

## Problems the book names

| Problem | What it looks like | Why instructions alone do not fix it |
|---|---|---|
| Claims exceed the evidence | A missing `Origin` check is reported as exploitable CSRF; a CVSS score looks precise although its inputs are guesses; a vulnerable dependency is reported even though the application never calls it | The source observation does not establish the browser behaviour, reachability or impact that the claim requires |
| Research standards stay implicit | "Be accurate" is the whole instruction; no project docs, examples of sound work or record of previous pitfalls | The agent has no concrete standard to apply and may choose tools that cannot answer the question |
| Validation stops with unanswered questions | The model refuses a needed step, or setup fails, and the report does not make the limit clear | An unresolved claim can still look like a completed assessment |
| A different answer looks like better research | Longer report, lower severity or a more cautious tone | None of these is evidence of improved research |

The proposed discipline is empirical: keep observation, interpretation and untested
hypothesis separate. A claim needs evidence that supports it **under the stated
conditions**. When evidence contradicts the claim, revise or reject it under those
conditions. When validation stops, retain the blocker, the unanswered question and a
permitted next action. Some blockers, including model refusals, may never be resolved.

## Components

The book adds a component only when it solves an observed research problem. Not every
harness needs every component.

| Component | Core idea |
|---|---|
| Local validation environment | A known, isolated way to run the target and the needed tools. "Working" means the intended app is reachable from the agent's tools, the tools function, and a harmless normal operation returns the expected result. Keep the toolset small and record the setup evidence. |
| Research state / memory | Preserve hypotheses, status, evidence, assumptions, environmental conditions, rejected paths, open questions and the next action. Preservation, discovery and retrieval are separate problems; stored data is not memory until it is selected and organized for reuse. |
| Context management | Choose what enters the context window. Too little information prevents assessment; too much irrelevant information can influence the answer. Filter tool output before it reaches the model (the book's weather example cuts ~12 KB to 34 bytes with `jq`). |
| External integrations / MCP | Use an external source when local files cannot answer the question. Bound the request, keep credentials and provenance, and treat response text as untrusted data. MCP helps when a workflow repeatedly needs several external capabilities; it does not make one record more authoritative. |
| Operational interfaces | Named commands for recurring actions and "views" for inspecting work. They reduce rediscovery and context churn. A view must expose existing work, not create a second copy that can disagree with it. |
| Telemetry | Deterministically record events where they happen (prompts, tool calls, durations, status), outside the agent's own account of its work. Telemetry reconstructs sessions and finds harness failures; it does not prove a finding or a security impact. |
| Skills | Reusable procedural instructions in a `SKILL.md` folder, optionally with references and assets. Skills improve consistency but **do not** provide determinism: the model still interprets the procedure. Tools still perform the actions. |
| Deterministic tools | Answer one defined, repeatable question (for example, an inventory query) and save the rule, source revision, raw output, coverage and limits. A scanner match does not establish attacker control, reachability or impact. Compare complete matched expressions, not counts. |
| Hooks | Configured behaviour at lifecycle events (`SessionStart`, `UserPromptSubmit`, `PreToolUse`, `PostToolUse`, `Stop`, `PreCompact`, `SessionEnd`). A hook can observe or block an action regardless of whether the model remembers an instruction. It is the git-hook idea applied to the agent loop. |
| Oracles | An interface to data the model lacks, so an open-ended question becomes a reproducible query. The book's Kubernetes RBAC example unpacked Helm charts into a searchable permissions database. An oracle supplies data; it does not make the security decision. |
| Reporting and disclosure | Decide report, hold or refute. Separate confidence from severity. Confirm the current release, source and private route before drafting. The agent drafts; a human judges and sends. No exercise sends or publishes anything. |

Information flow matters: capture, persistence and reuse are separate decisions. Data can
be used and discarded, or saved without entering another agent's context. Memory only
works when a later session can discover and retrieve it.

## Claims and evidence status

The book is unusually careful about what it has actually shown. Its status labels are
worth copying into SAK's own notes.

| Claim | Status in the book |
|---|---|
| A target-specific harness produces more inspectable research than a generic agent answer | The workshop's premise and exercise design, not a controlled result |
| Explicit claims/evidence discipline reduces overstatement | Argued from failure examples; the book does not claim a measured effect |
| A maintained deterministic inventory with conditional review can replace some repeated agent review | One local paired pilot on Argo revision `fbd338c…`: 4 sessions with the workflow vs 6 baseline, all ten inventories accurate, lower measured time but **higher uncached input tokens**; no token/cost saving or detection-improvement claim |
| Semgrep default ignores can hide relevant files | Observed coverage failure: `util/test/testutil.go` was omitted in the Argo pilot; corrected by enumerating tracked files and scanning a source-only mirror |
| Oracles improve blast-radius questions | A case study from the author's Kubernetes disclosure; no comparative measurement supplied |
| A readiness/report workflow improves disclosure quality | A planned comparison; no controlled workflow-benefit result claimed |

The recurring lesson: a pilot can support a narrow operational claim while leaving
accuracy, cost and teaching benefit unproven. Ties and negative results are valid.

## Exercises

The workshop is built around a preserved baseline and small checkpoints.

1. **Baseline.** Send one broad vulnerability-analysis request to an ordinary agent on an
   authorized open-source target. Save the request, response, source revision and the
   checks the agent actually performed.
2. **Choose one claim.** Identify its supporting evidence, the conditions it assumes and a
   check that could support or reject it. If there is no useful lead, select a security
   boundary to investigate rather than invent a vulnerability.
3. **Build one component.** Local validation, integration, interface, memory, context
   selection, telemetry, skill, deterministic tool, hook or oracle — whichever addresses
   an observed failure.
4. **Compare.** Repeat the work through the harness with model, task, evidence access,
   permissions and budget held constant. Inspect the evidence, not polish or length.
5. **Checkpoint.** Produce a setup record, a supported observation or a precise blocker,
   plus one justified next action. Retain the earlier result so the delta is inspectable.

The reporting exercise adds a report / hold / refute decision, a reproduction and control,
a named weakest link, the private route and a human-owned send. Synthetic material is
training-only. The deterministic-tools exercise adds a counterexample (same count, changed
expression; line-only move; normally ignored file) and scores missed/extra entries,
coverage gaps and unjustified skips.

## Limits and applicability

- The book is a workshop, not a measurement paper. Treat its pilot numbers as one local
  observation with human preparation, cache, latency and change-pattern confounders.
- Its examples assume an authorized local target and a coding agent that can run commands.
  Projects without a runnable target can still use research state, skills, deterministic
  source queries and disclosure discipline.
- A harness is not a sandbox. The book repeatedly separates instructions from enforcement:
  runtime isolation, tool permissions and network controls must sit outside the prompt.
- Adding components has maintenance cost. A one-off question may need only ordinary
  search; a maintained rule must justify its setup and review cost.
- Telemetry, hooks and oracles are visibility and data mechanisms. None of them
  establishes that a conclusion is correct.

See [sak-harness-map.md](sak-harness-map.md) for the component-by-component mapping to
SAK v1, including what is deferred.
