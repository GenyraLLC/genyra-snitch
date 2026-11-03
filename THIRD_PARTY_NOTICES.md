# Genyra Snitch third-party notices

Upstream Snitch copyright and license notices are preserved verbatim in
[docs/UPSTREAM_NOTICES.md](docs/UPSTREAM_NOTICES.md). That document describes
the historical upstream dependencies, including Python packages which the
native collector does not ship. Retained UI components and bundled data keep
their original notices and licenses. Cargo and npm lockfiles identify the
current Rust and compatibility UI dependencies.

The experimental Rust desktop uses egui/eframe and egui_extras (MIT/Apache-2.0),
image (MIT/Apache-2.0), reqwest (MIT/Apache-2.0), sysinfo (MIT), getrandom
(MIT/Apache-2.0) and serde_json (MIT/Apache-2.0). Their transitive dependencies
retain their respective licenses. Embedded Genyra logos originate from
genyra.com; source URLs and hashes are in ui/public/brand/PROVENANCE.json.

Npcap is an external Windows prerequisite. Its driver and runtime are not
redistributed by this project; obtain them from https://npcap.com/.
