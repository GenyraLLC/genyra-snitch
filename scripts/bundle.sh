#!/usr/bin/env bash
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"
version=$(sed -n 's/^version = "\([^"]*\)"/\1/p' Cargo.toml | head -1)
libc=$(getconf GNU_LIBC_VERSION | tr ' ' '-')
name="genyra-snitch-$version-linux-$(uname -m)-$libc"
output="$root/dist/releases/$version"
stage="$output/$name"
install -d "$stage/bin" "$stage/share/genyra-snitch/ui" "$stage/share/doc/genyra-snitch"
install -m 755 target/release/genyra-snitch "$stage/bin/genyra-snitch"
install -m 755 agent/target/release/snitch-agent "$stage/bin/snitch-agent"
cp -a ui/dist/. "$stage/share/genyra-snitch/ui/"
cp LICENSE README.md NOTICE UPSTREAM.json compatibility.json "$stage/share/doc/genyra-snitch/"
cp -a docs "$stage/share/doc/genyra-snitch/"
cp vendor/frida/PATCHES.md "$stage/share/doc/genyra-snitch/frida-patch.md"
tar -C "$output" -czf "$output/$name.tar.gz" "$name"
(cd "$output"; sha256sum "$name.tar.gz") > "$output/SHA256SUMS"
echo "$output/$name.tar.gz"
