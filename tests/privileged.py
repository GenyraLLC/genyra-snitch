#!/usr/bin/env python3
"""Root integration checks. Invoke ONLY via scripts/privileged-check.sh.
No route leaves the disposable network namespace; no production data is opened.
"""
import json,os,socket,subprocess,sys,tempfile,time,urllib.request,threading
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
assert os.geteuid()==0
assert os.readlink('/proc/self/ns/net') != os.readlink('/proc/1/ns/net'), 'Refusing to modify the host network namespace'
TOKEN='genyra-snitch-kernel-fixture-token'
BASE='http://127.0.0.1:18769'
report={}
def note(name,result):
    report[name]=result
    print(json.dumps({name:result}),flush=True)
    (ROOT/'checks/privileged-result.json').write_text(json.dumps(report,indent=2)+'\n')
def api(path,body=None,method=None):
    req=urllib.request.Request(BASE+path,None if body is None else json.dumps(body).encode(),{'X-Snitch-Token':TOKEN,'Content-Type':'application/json'},method=method)
    with urllib.request.urlopen(req,timeout=20) as r:return json.load(r)
def wait(fn,timeout=8):
    until=time.monotonic()+timeout
    while time.monotonic()<until:
        try:
            v=fn()
            if v:return v
        except (OSError,ValueError):pass
        time.sleep(.1)
    raise AssertionError('Timed out: '+str(fn))
def connects(ip='203.0.113.2',port=80,timeout=.6):
    try:
        with socket.create_connection((ip,port),timeout=timeout):return True
    except OSError:return False
peer=int(sys.argv[1]);server=None;backend=None;fixture=None
with tempfile.TemporaryDirectory(prefix='genyra-snitch-kernel-') as tmp:
    tmp=Path(tmp);data=tmp/'data';data.mkdir(mode=0o700)
    # A peer server listens only inside the other disposable namespace.
    server_code='''import socket,threading,time
for family,addr in [(socket.AF_INET,'203.0.113.2'),(socket.AF_INET6,'2001:db8:1::2')]:
 for port in [80,81,82]:
  s=socket.socket(family);s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);s.bind((addr,port));s.listen(64)
  def run(s=s):
   while True:
    c,_=s.accept();c.close()
  threading.Thread(target=run,daemon=True).start()
time.sleep(230)
'''
    server=subprocess.Popen(['nsenter','-t',str(peer),'-n','python3','-c',server_code])
    env=dict(os.environ,SNITCH_DATA_DIR=str(data),SNITCH_PORT='18769',SNITCH_BIND='127.0.0.1',SNITCH_IFACE='rs0',SNITCH_TOKEN=TOKEN,SNITCH_DISABLE_PTR='1')
    for key in ['SNITCH_REPLAY_PCAP','SNITCH_REPLAY_PCAP']:env.pop(key,None)
    import sqlite3
    c=sqlite3.connect(data/'snitch.db');c.execute('create table settings(key text primary key,value text not null)');c.execute("insert into settings values('integrity_watch','false')");c.commit();c.close()
    log=open(ROOT/'checks/privileged-stderr.log','wb')
    backend=subprocess.Popen([str(ROOT/'target/release/genyra-snitch')],env=env,stdout=log,stderr=log)
    try:
        wait(lambda:api('/capture/status')['capturing'])
        wait(connects)
        note('live_capture',wait(lambda:api('/diagnostics')['stats']['captured']>0))
        def add(action='block',kind='ip',value='203.0.113.2',**extras):
            r=api('/firewall/rules',dict(kind=kind,value=value,action=action,**extras))['rule'];assert r['applied'],r;return r['id']
        def delete(id):
            r=api('/firewall/rules/'+id,method='DELETE');assert r['ok'],r
        id=add();assert not connects();delete(id);assert connects();note('nft_ipv4_block',True)
        id=add(value='2001:db8:1::2');assert not connects('2001:db8:1::2');delete(id);assert connects('2001:db8:1::2');note('nft_ipv6_block',True)
        id=add(action='throttle',rate=8)
        u=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
        for _ in range(100):
            try:u.sendto(b'x'*1400,('203.0.113.2',19999))
            except PermissionError:pass
        u.close();time.sleep(.1)
        table=json.loads(subprocess.check_output(['nft','-j','list','table','inet','genyra_snitch']))
        counters=[expr['counter']['packets'] for item in table['nftables'] for expr in item.get('rule',{}).get('expr',[]) if 'counter' in expr]
        assert any(counters),table;delete(id);note('nft_throttle_drops',True)
        for ip in ['203.0.113.2','2001:db8:1::2']:
            id=add(action='sinkhole',value=ip)
            wait(lambda:api('/security/sinkhole')['listening']['80'])
            opener=urllib.request.build_opener(urllib.request.ProxyHandler({}))
            url='http://'+('['+ip+']' if ':' in ip else ip)+'/'
            with opener.open(url,timeout=3) as r:assert r.status==204
            hit=api('/security/sinkhole')['hits'][-1];assert hit['original_dst'],hit
            delete(id)
        note('sinkhole_ipv4_ipv6',True)
        assert api('/firewall/lockdown',{'on':True})['ok'];assert not connects()
        assert api('/firewall/lockdown',{'on':False})['ok'];assert connects();note('lockdown',True)
        api('/settings',{'settings':{'ask_enabled':True,'ask_timeout':3,'ask_failopen':False}})
        wait(lambda:api('/security/ask')['running'])
        results=[]
        thread=threading.Thread(target=lambda:results.append(connects(port=81,timeout=5)));thread.start()
        wait(lambda:api('/security/ask')['pending']>0)
        assert api('/security/ask/verdict',{'remote_ip':'203.0.113.2','remote_port':81,'proto':'TCP','allow':True})['ok']
        thread.join(6);assert results==[True],results
        results=[];thread=threading.Thread(target=lambda:results.append(connects(port=82,timeout=4)));thread.start()
        wait(lambda:api('/security/ask')['pending']>0)
        assert api('/security/ask/verdict',{'remote_ip':'203.0.113.2','remote_port':82,'proto':'TCP','allow':False})['ok']
        thread.join(5);assert results==[False],results
        api('/settings',{'settings':{'ask_enabled':False}});wait(lambda:not api('/security/ask')['running']);note('nfqueue_allow_deny',True)
        api('/settings',{'settings':{'ebpf_probe':True}})
        wait(lambda:api('/security/ebpf')['active'])
        before=api('/security/ebpf')['events_total'];connects();wait(lambda:api('/security/ebpf')['events_total']>before);note('ebpf_connect_probe',True)
        subprocess.run(['cc',str(ROOT/'tests/fixtures/inspection-target.c'),'-o',str(tmp/'fixture')],check=True)
        fixture_log=open(tmp/'connections.log','w')
        fixture=subprocess.Popen([str(tmp/'fixture'),'203.0.113.2'],stdout=fixture_log)
        def tail():return (tmp/'connections.log').read_text().splitlines()[-4:]
        wait(lambda:tail()==['1']*4)
        id=add(kind='process',value='snitch-fixture')
        wait(lambda:'genyra-snitch-deny-' in Path('/proc/'+str(fixture.pid)+'/cgroup').read_text())
        wait(lambda:tail()==['0']*4)
        delete(id);wait(lambda:'genyra-snitch-deny-' not in Path('/proc/'+str(fixture.pid)+'/cgroup').read_text());wait(lambda:tail()==['1']*4);note('process_cgroup_policy',True)
        assert api('/security/ebpf/block',{'ip':'203.0.113.2'})['ok']
        assert api('/security/ebpf/isolate',{'pid':fixture.pid})['ok']
        assert fixture.pid in api('/security/ebpf_enforce')['isolated_pids'];wait(lambda:tail()==['0']*4);note('ebpf_egress_drops',True)
        perf=api('/security/perf',{'pid':fixture.pid,'seconds':.2});note('hardware_perf',perf)
        sandbox=api('/security/sandbox',{'path':'/usr/bin/true','seconds':2});note('sandbox',sandbox)
        api('/shutdown',{});backend.wait(timeout=10);assert backend.returncode==0
        note('clean_shutdown',True)
    except Exception as exc:
        note('failure',repr(exc));raise
    finally:
        if backend.poll() is None:
            try:api('/shutdown',{});backend.wait(timeout=10)
            except Exception:backend.kill();backend.wait()
        if fixture and fixture.poll() is None:fixture.terminate();fixture.wait()
        if server and server.poll() is None:server.terminate();server.wait()
        subprocess.run(['kill',str(peer)],check=False)
        log.close()
