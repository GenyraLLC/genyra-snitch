#!/usr/bin/env bash
# Inspect the staged public tree, never local capture/database contents.
set -euo pipefail
cd "$(dirname "$0")/.."
python3 - <<'PY'
from pathlib import Path
import subprocess,re
files=subprocess.check_output(['git','ls-files','--cached','--stage'],text=True).splitlines()
bad=[]
for line in files:
    metadata,name=line.split('\t',1)
    if metadata.startswith('160000 '):continue
    p=Path(name)
    if not p.is_file():continue
    if name.startswith(('local-workstation/','checks/','data/','dist/')) or '/node_modules/'in name or '/target/'in name or name.endswith(('.pcap','.db','.db-wal','.db-shm','.pem','.key','.p12','.pfx','.core')) or p.name=='api_token.txt':bad.append(name)
    if p.suffix in ('.png','.der','.gz','.ico'):continue
    if name=='scripts/audit-public.sh':continue
    text=p.read_text(errors='replace')
    if re.search(r'/home/[^/\s]+/(?:Work|Desktop|Documents|Downloads)/',text) or any(value in text for value in ('/Work/rift-','SNITCH_ATTACH_PORT','comparison-session.json')):bad.append(name)
    if re.search(r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----',text):bad.append(name)
assert not bad, sorted(set(bad))
print('Public tree audit passed: no workstation integration, capture, database or private key files.')
PY
