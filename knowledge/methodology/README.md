# Methodology notes

Research notes behind SAK's harness and eval design. These are summaries with attribution,
not vendored source and not a replacement for reading the originals.

| File | Contents |
|---|---|
| [harness-engineering.md](harness-engineering.md) | Notes on *Introduction To Harness Engineering For Vulnerability Research* (Helton and Basden): components, claims, exercises, limits |
| [sak-harness-map.md](sak-harness-map.md) | Component-by-component mapping to SAK v1, with what is partial or deferred |
| [ci-pentest-harness.md](ci-pentest-harness.md) | Notes on the Zenn OpenCode + Docker + GitHub Actions pentest setup and its mapping to a future `sak ci` mode |

The measurable loop and evidence standard live in
[`docs/improvement-loop.md`](../../docs/improvement-loop.md).

## Sources

- Graham Helton and Ryan Basden, *Introduction To Harness Engineering For Vulnerability
  Research* — <https://grahamhelton.github.io/harness-engineering-workshop-book/print.html>
  (retrieved 2026-11-11).
- dyoshikawa, *OpenCode+Docker+GitHub Actionsで全自動AIペネトレーションテストはじめました*,
  Zenn Tech Blog, 2026-11-04 —
  <https://zenn.dev/team_zenn/articles/opencode-docker-actions-ai-pentest>
  (retrieved 2026-11-11).

Both sources are linked for reference and summarised in our own words. No book or article
text is mirrored here. See `docs/source-decisions.md` (T9) for the pack's license and
adoption decisions.
