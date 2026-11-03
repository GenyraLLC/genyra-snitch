#!/usr/bin/env bash
# Synthetic launchd check on disposable CI runners; never changes an existing job.
set -euo pipefail
backend="$(pwd)/target/release/genyra-snitch"
registration="$HOME/Library/LaunchAgents/com.genyra.snitch.plist"
domain="gui/$(id -u)"
test ! -e "$registration" || { echo 'Refusing to modify an existing Genyra LaunchAgent'; exit 1; }
launchctl print "$domain" >/dev/null
data="$(mktemp -d)"
installed=false
cleanup() {
  if "$installed"; then "$backend" service uninstall --data-dir "$data"; fi
  rm -rf "$data"
}
trap cleanup EXIT
"$backend" service install --data-dir "$data"
installed=true
/usr/libexec/PlistBuddy -c 'Add :ProgramArguments:1 string --demo' "$registration"
plutil -lint "$registration"
request() {
  printf 'header = "X-Snitch-Token: %s"\n' "$token" | curl --config - --silent --show-error --fail --connect-timeout 1 --max-time 3 "$@"
}
previous_token=''
for round in 1 2; do
  "$backend" service start --data-dir "$data"
  ready=false
  for attempt in {1..200}; do
    if [[ -s "$data/collector.json" && -s "$data/api_token.txt" ]]; then
      base="$(jq -r .url "$data/collector.json")"
      token="$(cat "$data/api_token.txt")"
      if request "$base/diagnostics" > "$data/diagnostics.json" 2>/dev/null; then
        jq -e '.product == "Genyra Snitch" and .capture.demo == true' "$data/diagnostics.json" >/dev/null
        ready=true
        break
      fi
    fi
    sleep .1
  done
  "$ready" || { echo 'launchd collector did not become ready'; exit 1; }
  if [[ "$round" == 1 ]]; then
    previous_token="$token"
    request "$base/settings" -H 'Content-Type: application/json' -d '{"settings":{"retention_hours":73}}' >/dev/null
  else
    [[ "$token" == "$previous_token" ]]
    request "$base/settings" | jq -e '.settings.retention_hours == 73' >/dev/null
  fi
  "$backend" service stop --data-dir "$data"
  for attempt in {1..200}; do
    [[ -e "$data/collector.json" ]] || break
    sleep .1
  done
  test ! -e "$data/collector.json"
done
echo 'macOS launchd start, stop, restart, identity and persistence checks passed (synthetic data).'
