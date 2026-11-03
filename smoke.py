#!/usr/bin/env python3
"""Development-only compatibility checks; the deployed collector is Rust."""
import base64
import concurrent.futures
import json
import os
from pathlib import Path
import secrets
import socket
import sqlite3
import struct
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

ROOT = Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT/"tests"))
from traffic_fixture import interface,write_pcap


def main():
    with tempfile.TemporaryDirectory(prefix="genyra-snitch-") as temp:
        temp = Path(temp)
        data = temp / "data"
        data.mkdir()
        iface=interface()
        fixture_pcap=write_pcap(temp/"fixture.pcap",iface)
        token = secrets.token_hex(32)
        (data / "api_token.txt").write_text(token)
        env = dict(os.environ, SNITCH_DATA_DIR=str(data), SNITCH_PORT="18767", SNITCH_IFACE=iface, SNITCH_FRONTEND_DIR=str(ROOT / "ui/dist"), SNITCH_REPLAY_PCAP=str(fixture_pcap))
        binary = Path(os.environ.get("SNITCH_TEST_BINARY", ROOT / "target/release/genyra-snitch"))
        subprocess.run([binary, "--check"], env=env, check=True, stdout=subprocess.DEVNULL)
        process = subprocess.Popen([binary], env=env, stdout=subprocess.PIPE, stderr=open(ROOT/"checks/smoke-stderr.log","wb"))

        def request(path, body=None, method=None, auth=True, origin=None, agent=None):
            headers = {"X-Snitch-Token": token} if auth else {}
            if agent:
                headers["X-Snitch-Agent"] = agent
            if origin:
                headers["Origin"] = origin
            encoded = json.dumps(body).encode() if body is not None else None
            if encoded:
                headers["Content-Type"] = "application/json"
            req = urllib.request.Request("http://127.0.0.1:18767" + path, encoded, headers, method=method)
            try:
                with urllib.request.urlopen(req, timeout=25) as response:
                    raw = response.read()
                    if response.headers.get("Content-Type", "").startswith("application/json"):
                        raw = json.loads(raw)
                    return response.status, raw
            except urllib.error.HTTPError as error:
                raw = error.read()
                try:
                    raw = json.loads(raw)
                except ValueError:
                    raw = raw.decode(errors="replace")
                return error.code, raw

        fixture=None
        try:
            for _ in range(100):
                if process.poll() is not None:
                    raise RuntimeError((ROOT/"checks/smoke-stderr.log").read_text())
                try:
                    status, diag = request("/diagnostics")
                    if status == 200 and diag["stats"]["captured"] > 0:
                        break
                except OSError:
                    pass
                time.sleep(0.05)
            else:
                raise AssertionError("Native replay did not become ready")

            assert request("/graph", auth=False)[0] == 401
            assert request("/graph", origin="https://attacker.invalid")[0] == 403
            assert request("/graph?token=" + token, auth=False)[0] == 200
            assert request("/", auth=False)[0] == 200
            assert request("/brand/genyra-icon.png",auth=False)[1].startswith(b"\x89PNG")
            assert request("/favicon.png",auth=False)[1].startswith(b"\x89PNG")
            assert b"<html" in request("/", auth=False)[1].lower()
            graph = request("/graph")[1]
            assert len(graph["nodes"]) > 1 and graph["edges"]
            assert all("bytes" in n for n in graph["nodes"])
            if diag["geo_city_loaded"]:
                assert any(n.get("country") and n.get("lat") is not None for n in graph["nodes"])
            assert diag["stats"]["processed"] > 100
            assert request("/watchlist")[1].get("items")==[]

            endpoints = ["/graph", "/devices", "/alerts", "/capture/status", "/capture/interfaces", "/settings", "/geo/status", "/watchlist", "/remote/pairing", "/alerts/ignore", "/alerts/rules", "/firewall/status", "/firewall/rules", "/firewall/profiles", "/security/integrity", "/security/ti", "/security/slm", "/security/audit", "/security/explain?type=NEW_HOST", "/history/top_processes", "/history/host/8.8.8.8", "/history/process/brave"]
            with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
                results = list(pool.map(request, endpoints))
            for endpoint, (status, _) in zip(endpoints, results):
                assert status == 200, (endpoint, status)

            assert request("/settings", {"settings": {"language": "en", "upload_threshold_mb": 80}})[0] == 200
            assert request("/settings")[1]["settings"]["language"] == "en"
            assert request("/capture/whitelist", {"ips": ["not-an-ip"]})[0] == 400
            assert request("/watchlist", {"items": ["example.com"]})[1]["items"] == ["example.com"]
            assert request("/watchlist")[1]["items"] == ["example.com"]
            rule = request("/alerts/rules", {"name": "test", "field": "remote_ip", "op": "cidr", "value": "10.0.0.0/8", "severity": "warning"})[1]["rule"]
            assert request("/alerts/rules/" + rule["id"], method="DELETE")[0] == 200
            agent = request("/ingest/enroll", {"name": "smoke-agent"})[1]
            assert agent["token"].startswith("sagt_")
            assert "smoke-agent" in request("/ingest/agents")[1]["agents"]
            agent_token=agent["token"]
            assert request("/ingest/events", {"agent":"forged","events":[]}, auth=False, agent=agent_token)[0]==200
            assert request("/graph", auth=False, agent=agent_token)[0]==401
            assert request("/ingest/revoke", {"name": "smoke-agent"})[0] == 200
            assert request("/ingest/events", {"events":[]}, auth=False, agent=agent_token)[0]==401
            assert request("/graph",origin="null")[0]==200
            explanation=request("/security/explain?type=NEW_HOST")[1]
            assert "title_en" in explanation, explanation
            assert request("/alerts/ignore",{"type":"","ip":"8.8.8.8"})[1]["suppressions"]==[{"type":"","ip":"8.8.8.8"}]
            assert request("/alerts/ignore",{"type":"","ip":"8.8.8.8"},method="DELETE")[1]["suppressions"]==[]
            assert request("/forensics/export?format=csv")[1].startswith(b"section,field,value")
            assert request("/forensics/export?format=stix")[1]["objects"][0]["type"]=="identity"
            for line in request("/forensics/export?format=ecs")[1].splitlines():
                event=json.loads(line);assert "observer" in event and event["event"]["kind"]=="alert"
            subprocess.run(["cc",str(ROOT/"tests/fixtures/inspection-target.c"),"-o",str(temp/"fixture")],check=True)
            fixture=subprocess.Popen([str(temp/"fixture")])
            time.sleep(.2)
            deep=request("/security/deep_inspect",{"pid":fixture.pid,"seconds":3})[1]
            assert deep["ok"],deep
            assert deep["events"] or deep["flows"],deep
            hollow=request("/security/hollow",{"pid":fixture.pid})[1]
            assert hollow["ok"],hollow
            perf=request("/security/perf",{"pid":fixture.pid,"seconds":.2})[1]
            assert "ok" in perf
            route_results=[]
            for route in json.loads((ROOT/"compatibility.json").read_text())["routes"]:
                method,path=route["method"],route["path"]
                if method=="WEBSOCKET" or path=="/shutdown":continue
                path=path.replace("{ip}","8.8.8.8").replace("{name}","fixture").replace("{rule_id}","missing-test-rule")
                payload={"pid":0} if method!="GET" else None
                if path=="/security/explain":path+="?type=NEW_HOST"
                if path=="/settings" and method=="POST":payload={"settings":{}}
                status,_=request(path,payload,method=method)
                assert status in (200,204,400,404,422),(method,path,status)
                route_results.append({"method":method,"path":path,"status":status})
            (ROOT/"checks/route-results.json").write_text(json.dumps(route_results,indent=2)+"\n")
            pack = request("/security/iocpack?format=proof")[1]
            assert pack["format"] == "snitch-ioc-proof/1"
            assert request("/security/iocpack/import", {"pack": pack})[1]["ok"]
            pack["root"] = "bad"
            assert not request("/security/iocpack/import", {"pack": pack})[1]["ok"]

            sock = socket.create_connection(("127.0.0.1", 18767), timeout=4)
            key = base64.b64encode(secrets.token_bytes(16)).decode()
            sock.sendall((f"GET /ws?token={token} HTTP/1.1\r\nHost: 127.0.0.1:18767\r\nOrigin: http://127.0.0.1:18767\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n").encode())
            stream = sock.makefile("rb")
            headers = []
            while (line := stream.readline()) != b"\r\n":
                headers.append(line)
            assert b"101" in headers[0]
            first, length = stream.read(2)
            length &= 127
            if length == 126:
                length = struct.unpack("!H", stream.read(2))[0]
            elif length == 127:
                length = struct.unpack("!Q", stream.read(8))[0]
            init = json.loads(stream.read(length))
            assert init["type"] == "init" and len(init["nodes"]) > 1
            stream.close()
            sock.close()

            started = time.monotonic()
            with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
                snapshots = list(pool.map(lambda _: request("/graph")[0], range(60)))
            assert snapshots == [200] * 60
            elapsed = time.monotonic() - started
            request("/shutdown", {})
            process.wait(timeout=8)
            assert process.returncode == 0
            connection = sqlite3.connect(data / "snitch.db")
            assert connection.execute("select sum(bytes) from traffic").fetchone()[0] > 0
            assert json.loads(connection.execute("select value from settings where key='language'").fetchone()[0]) == "en"
            connection.close()
            report = {"replay_frames": diag["stats"]["captured"], "processed_packets": diag["stats"]["processed"], "nodes": len(graph["nodes"]), "rest_endpoints_checked": len(endpoints), "concurrent_graph_requests": 60, "graph_requests_seconds": round(elapsed, 3), "websocket_init": "passed", "authentication": "passed", "persistence_after_shutdown": "passed", "live_capture": "not tested", "legacy_route_responses":len(route_results)+2,"frida_own_fixture":"passed","hollow_own_fixture":"passed"}
            (ROOT / "checks/smoke-result.json").write_text(json.dumps(report, indent=2) + "\n")
            print(json.dumps(report, indent=2))
        finally:
            if fixture and fixture.poll() is None:
                fixture.terminate();fixture.wait(timeout=3)
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=8)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()


if __name__ == "__main__":
    main()
