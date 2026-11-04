# Native gallery — Linux alpha

These are actual renders of Genyra Snitch **0.1.0-alpha.5**, with entirely
fictional example data from the [Rust gallery fixture](../../examples/gallery_fixture.rs).
The header says **SYNTHETIC DEMO · fictional traffic**. They are UI illustrations,
not captures of a customer's network or evidence of real threat detection.

The fixture does not capture traffic, inspect processes, query devices, resolve
names or contact external services. It uses documentation addresses
`192.0.2.0/24` and `198.51.100.0/24`, reserved `.example` hostnames, fictional
device/app names, locally generated demonstration MACs and example alerts.
No personal servers, Hetzner/storage-box identifiers, workstation names, private
connections, tokens or real devices are used. PNGs come from the native framebuffer,
not a desktop screenshot containing other applications.

- [Light mode](native-light.png)
- [Dark mode](native-dark.png)
- [Image hashes and provenance](PROVENANCE.json)

To reproduce without live capture or elevated permissions:

```sh
cargo build --release --locked --example gallery_fixture
./target/release/examples/gallery_fixture --data-dir /tmp/genyra-gallery
# In another terminal, with the native desktop built:
./desktop/target/release/genyra-snitch-desktop \
  --connect http://127.0.0.1:18987 \
  --token-file /tmp/genyra-gallery/api_token.txt \
  --data-dir /tmp/genyra-gallery/ui-light \
  --theme light --language en --screenshot /tmp/native-light.png
```

Use a 1440 × 1040 logical-pixel window before the automatic screenshot. Repeat
with `--theme dark` and a new output filename for dark mode. The fixture rejects
mutation requests and is not a production collector. Stop it with Ctrl+C.
