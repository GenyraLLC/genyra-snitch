# Contributing

Keep the upstream API and UI workflows compatible unless a change is explicitly documented. Add meaningful tests for parser edge cases, rule semantics, persistence or privileged effects. Use generated fixtures, never a personal packet capture or production database.

Run `scripts/check.sh` before sending a pull request. Kernel integration checks must run through `scripts/privileged-check.sh`, which creates disposable network namespaces. Do not run firewall experiments directly against a workstation policy.

Include the concrete behavior changed, validation performed and any limits. Keep upstream attribution intact. Follow Rust formatting and Clippy checks, and preserve the existing React language support.
