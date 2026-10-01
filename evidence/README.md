# Evidence

All files are sanitized summaries. They contain no credentials (no Signal account was used),
no message contents, and no raw NetLogs or job logs.

| Directory / file | Class | Produced by |
|---|---|---|
| `ci/local/` | LOCAL, real browsers on GitHub-hosted runners | `.github/workflows/browser-local-tests.yml` → `tools/run-local-tests.mjs`, `tools/run-upstream-tests.mjs` |
| `ci/live/` | LIVE (contacts Signal's public hosts, no account), real browsers on GitHub-hosted runners with direct internet | `.github/workflows/browser-live-probe.yml` → `tools/run-probe.mjs` |
| `local/*.json` | LOCAL, Chromium in the authoring container | same tools, run locally |
| `local/libsignal-net-wasm-build.md` | LOCAL build experiment | see file |
| `live/tls-trust-summary.json` | LIVE, **non-browser** (openssl, Certificate Transparency, CCADB) | `tools/tls_trust_evidence.py` |
| `live/server-behavior-diagnostic.json` | LIVE, **non-browser** (curl trusting only Signal's pinned root) | `tools/server_behavior_diagnostic.py` |
| `live/probe-pw-chromium-cloud-container-direct.json` | LIVE, but **INVALID for Signal conclusions**: the authoring container's network re-terminates browser TLS with its own interception CA (see its `verdict` and `netlog`). Kept only to document why container browser results were not used. | `tools/run-probe.mjs` |

Files in `ci/` carry a `ci_run` field with the GitHub Actions run URL. They were recovered
from job logs with `tools/extract-ci-evidence.mjs`. The tables in `VALIDATION_REPORT.md` are
generated from them by `tools/summarize-evidence.mjs`.
