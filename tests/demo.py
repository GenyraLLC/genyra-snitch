#!/usr/bin/env python3
import json,os,subprocess,tempfile,time,urllib.request,urllib.error
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
with tempfile.TemporaryDirectory(prefix='genyra-snitch-demo-')as tmp:
    env=dict(os.environ,SNITCH_DATA_DIR=tmp,SNITCH_TOKEN='genyra-snitch-demo-test-token',SNITCH_PORT='18772',SNITCH_IFACE='lo')
    p=subprocess.Popen([str(ROOT/'target/release/genyra-snitch'),'--demo'],env=env,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    def req(path,body=None):
        r=urllib.request.Request('http://127.0.0.1:18772'+path,None if body is None else json.dumps(body).encode(),{'X-Snitch-Token':env['SNITCH_TOKEN'],'Content-Type':'application/json'})
        return urllib.request.urlopen(r,timeout=3)
    try:
        for _ in range(60):
            try:
                with req('/graph')as r:graph=json.load(r)
                if len(graph['nodes'])>=4:break
            except OSError:pass
            time.sleep(.1)
        else:raise AssertionError('No synthetic graph')
        with req('/capture/status')as r:assert json.load(r)['demo']
        with req('/forensics/pcap')as r:assert r.status==204
        try:req('/processes/kill',{'pid':os.getpid()})
        except urllib.error.HTTPError as e:assert e.code==400
        else:raise AssertionError('Demo permitted process mutation')
        with req('/shutdown',{})as r:assert r.status==200
        p.wait(timeout=8);assert p.returncode==0
        (ROOT/'checks/demo-result.json').write_text(json.dumps({'synthetic_graph':True,'no_wire_pcap':True,'process_mutations_refused':True})+'\n')
        print('Native demo passed')
    finally:
        if p.poll()is None:p.terminate();p.wait(timeout=8)
