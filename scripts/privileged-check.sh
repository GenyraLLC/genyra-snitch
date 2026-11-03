#!/usr/bin/env bash
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
if [[ ${1:-} != --inside ]]; then
  [[ $EUID == 0 ]] || { echo 'Run this test with pkexec or sudo.' >&2; exit 1; }
  exec unshare --net --mount --fork "$0" --inside
fi
mount --make-rprivate /
unshare --net sleep 240 & peer=$!
trap 'kill "$peer" 2>/dev/null || true; wait "$peer" 2>/dev/null || true' EXIT
for attempt in {1..50}; do
  if nsenter -t "$peer" -n ip link set lo up 2>/dev/null; then break; fi
  sleep .05
done
ip link set lo up
ip link add rs0 type veth peer name rs1
ip link set rs1 netns "$peer"
ip addr add 203.0.113.1/24 dev rs0
ip -6 addr add 2001:db8:1::1/64 dev rs0 nodad
ip link set rs0 up
nsenter -t "$peer" -n ip addr add 203.0.113.2/24 dev rs1
nsenter -t "$peer" -n ip -6 addr add 2001:db8:1::2/64 dev rs1 nodad
nsenter -t "$peer" -n ip link set rs1 up
exec python3 "$root/tests/privileged.py" "$peer"
