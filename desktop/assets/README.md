# Native desktop assets

The static locale strings in `locales/upstream.json` derive from aiXis Studio's
Snitch dictionaries, retained under the upstream AGPL licence. Dynamic labels
are implemented in Rust. `locales/native.json` contains Genyra's additional UI
labels, with the same keys in all eight locales. Captured hostnames, protocol
identifiers and collector-provided messages are preserved as received.

`fonts/GenyraUIFallback.otf` is a renamed subset of Noto Sans CJK Regular, used
after the default native UI fonts. It includes the glyphs used by the bundled
translations and language names. Its SIL Open Font License is retained in
`fonts/OFL-Noto.txt`. Source: https://github.com/notofonts/noto-cjk.

The JSON and font are checked in; building and running the app needs no Node or
Python runtime. Optional maintenance commands, from the repository root:

```sh
node scripts/sync-native-locales.mjs
# Requires the development-only fonttools package and the original font file:
python scripts/subset-native-font.py --font /path/to/NotoSansCJK-Regular.ttc
```

Genyra wordmarks are the official assets in `ui/public/brand`, with their source
URLs recorded in that directory's provenance file. The clickable wordmark opens
https://genyra.com only when the user activates it.
