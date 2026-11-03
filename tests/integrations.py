#!/usr/bin/env python3
"""Loopback-only integration fixtures for notifications, peers, models and TLS."""
import json,os,socket,ssl,subprocess,tempfile,threading,time,urllib.request
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
from traffic_fixture import write_pcap
TOKEN='genyra-snitch-local-integration-token'
received=[];calls=[]
class Mock(BaseHTTPRequestHandler):
    def log_message(self,*args):pass
    def reply(self,v):
        b=json.dumps(v).encode();self.send_response(200);self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(b)));self.end_headers();self.wfile.write(b)
    def do_GET(self):
        calls.append(self.path)
        self.reply({'models':[{'name':'fixture-model'}]} if self.path=='/api/tags' else {'score':97,'critical':0,'warning':0})
    def do_POST(self):
        body=json.loads(self.rfile.read(int(self.headers.get('Content-Length',0))));calls.append(self.path)
        if self.path=='/webhook':received.append(body)
        self.reply({'response':'Fixture local explanation.'} if self.path=='/api/generate' else {'ok':True})
def api(path,body=None):
    q=urllib.request.Request(BASE+path,None if body is None else json.dumps(body).encode(),{'X-Snitch-Token':TOKEN,'Content-Type':'application/json'})
    with opener.open(q,timeout=20)as r:return json.load(r)
def wait(fn,seconds=8):
    until=time.monotonic()+seconds
    while time.monotonic()<until:
        try:
            v=fn()
            if v:return v
        except OSError:pass
        time.sleep(.1)
    raise AssertionError('Fixture timed out')
with tempfile.TemporaryDirectory(prefix='genyra-snitch-integration-')as temp:
    temp=Path(temp);data=temp/'data';data.mkdir(mode=0o700)
    mock=ThreadingHTTPServer(('127.0.0.1',0),Mock);threading.Thread(target=mock.serve_forever,daemon=True).start();mockport=mock.server_address[1]
    udp=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);udp.bind(('127.0.0.1',0));udp.settimeout(5)
    cert=temp/'cert.pem';key=temp/'key.pem'
    subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-keyout',str(key),'-out',str(cert),'-days','1','-subj','/CN=localhost','-addext','subjectAltName=IP:127.0.0.1,DNS:localhost'],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    ctx=ssl.create_default_context(cafile=str(cert));opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),urllib.request.HTTPSHandler(context=ctx))
    BASE='https://127.0.0.1:18771'
    env=dict(os.environ,SNITCH_DATA_DIR=str(data),SNITCH_IFACE='lo',SNITCH_BIND='127.0.0.1',SNITCH_TOKEN=TOKEN,SNITCH_PORT='18771',SNITCH_DISABLE_PTR='1',SNITCH_REPLAY_PCAP=str(write_pcap(temp/'fixture.pcap','lo')),SNITCH_TLS_CERT=str(cert),SNITCH_TLS_KEY=str(key))
    log=open(ROOT/'checks/integration-stderr.log','wb')
    backend=subprocess.Popen([str(ROOT/'target/release/genyra-snitch')],env=env,stdout=log,stderr=log)
    try:
        wait(lambda:api('/graph'))
        settings={'slm_enabled':True,'slm_endpoint':f'http://127.0.0.1:{mockport}','slm_mode':'ollama','gossip_peers':[f'http://127.0.0.1:{mockport}'],'webhook_enabled':True,'webhook_url':f'http://127.0.0.1:{mockport}/webhook','syslog_addr':f'udp://127.0.0.1:{udp.getsockname()[1]}','syslog_format':'cef'}
        api('/settings',{'settings':settings})
        status=api('/security/slm');assert status['reachable'],status
        explanation=api('/security/explain',{'type':'NEW_HOST','details':{'ip':'203.0.113.5'},'lang':'en'})
        assert 'Fixture local explanation.' in str(explanation),explanation
        count=calls.count('/api/generate');api('/security/explain',{'type':'NEW_HOST','details':{'ip':'203.0.113.5'},'lang':'en'});assert calls.count('/api/generate')==count
        sync=api('/remote/ioc_sync',{});assert sync['ok'],sync
        fleet=api('/remote/fleet');assert fleet['reachable']==1 and fleet['worst_score']==97,fleet
        rule=api('/alerts/rules',{'name':'integration rule','field':'process_name','op':'eq','value':'integration-fixture','severity':'critical'})
        payload={'host':'fixture','events':[{'remote_ip':'203.0.113.5','dst_ip':'203.0.113.5','dst_port':443,'process_name':'integration-fixture','process':'integration-fixture','size':100,'proto':'tcp','direction':'out'}]}
        ingested=api('/ingest/events',payload);assert ingested['alerts']>0,ingested
        wait(lambda:received)
        message=udp.recv(8192);assert b'CEF:0|Genyra LLC' in message,message
        assert received[-1]['alert']['type']=='CUSTOM_RULE'
        result={'https_verified_certificate':True,'local_model_and_cache':True,'ioc_peer_exchange':True,'fleet':True,'custom_rules_on_agent_events':True,'webhook':True,'syslog_cef_udp':True}
        (ROOT/'checks/integration-result.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result,indent=2))
    finally:
        if backend.poll()is None:
            try:api('/shutdown',{});backend.wait(timeout=10)
            except Exception:backend.kill();backend.wait()
        mock.shutdown();mock.server_close();udp.close();log.close()
