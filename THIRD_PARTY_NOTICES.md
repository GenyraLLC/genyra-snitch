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

The native overview retains static UI translations from aiXis Studio's Snitch
(`ui/src/locales`, AGPL-3.0-or-later), alongside Genyra's native labels in
`desktop/assets/locales/native.json`. Native drawing and layout are implemented
independently in Rust; the upstream graph is the design reference.

The bundled **Genyra UI Fallback** font is a renamed glyph subset of
[Noto Sans CJK](https://github.com/notofonts/noto-cjk), with the source font's
copyright **© 2014–2021 Adobe**, under the SIL Open Font License 1.1. The retained license is
[desktop/assets/fonts/OFL-Noto.txt](desktop/assets/fonts/OFL-Noto.txt).

Npcap is an external Windows prerequisite. Its driver and runtime are not
redistributed by this project; obtain them from https://npcap.com/.
