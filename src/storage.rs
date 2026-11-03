use crate::state::Pending;
use rusqlite::{params, Connection};
use serde_json::{json, Value};
use std::path::Path;

pub fn open(data: &Path) -> rusqlite::Result<Connection> {
    let c = Connection::open(data.join("snitch.db"))?;
    c.busy_timeout(std::time::Duration::from_secs(2))?;
    c.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL;
        CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY,value TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS traffic(minute TEXT NOT NULL,category TEXT NOT NULL,packets INTEGER DEFAULT 0,bytes INTEGER DEFAULT 0,PRIMARY KEY(minute,category));
        CREATE TABLE IF NOT EXISTS history(minute TEXT NOT NULL,dim TEXT NOT NULL,key TEXT NOT NULL,packets INTEGER DEFAULT 0,bytes INTEGER DEFAULT 0,PRIMARY KEY(minute,dim,key));
        CREATE TABLE IF NOT EXISTS alerts_log(id TEXT PRIMARY KEY,ts TEXT NOT NULL,type TEXT,severity TEXT,message TEXT,node_id TEXT,details TEXT);
        CREATE TABLE IF NOT EXISTS devices(ip TEXT PRIMARY KEY,mac TEXT,vendor TEXT,device_type TEXT,hostname TEXT,private_mac INTEGER DEFAULT 0,first_seen TEXT,last_seen TEXT);
        CREATE INDEX IF NOT EXISTS idx_alerts_ts ON alerts_log(ts);
        CREATE INDEX IF NOT EXISTS idx_history_lookup ON history(dim,key,minute);")?;
    Ok(c)
}
pub fn settings(c: &Connection) -> rusqlite::Result<Value> {
    let mut out = json!({});
    let mut s = c.prepare("SELECT key,value FROM settings")?;
    for row in s.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))? {
        let (k, v) = row?;
        if let Ok(v) = serde_json::from_str::<Value>(&v) {
            out[k] = v;
        }
    }
    Ok(out)
}
pub fn alerts(c: &Connection) -> rusqlite::Result<Vec<Value>> {
    alerts_limit(c, 100)
}
pub fn alerts_limit(c: &Connection, limit: usize) -> rusqlite::Result<Vec<Value>> {
    let mut s=c.prepare("SELECT id,ts,type,severity,message,node_id,details FROM alerts_log ORDER BY ts DESC LIMIT ?1")?;
    let rows = s.query_map([limit.min(10000) as i64],|r|Ok(json!({"id":r.get::<_,String>(0)?,"timestamp":r.get::<_,String>(1)?,"type":r.get::<_,Option<String>>(2)?,"severity":r.get::<_,Option<String>>(3)?,"message":r.get::<_,Option<String>>(4)?,"node_id":r.get::<_,Option<String>>(5)?,"details":r.get::<_,Option<String>>(6)?.and_then(|s|serde_json::from_str::<Value>(&s).ok()).unwrap_or(json!({}))})))?.collect();
    rows
}
pub fn devices(c: &Connection) -> rusqlite::Result<Vec<Value>> {
    let mut s=c.prepare("SELECT ip,mac,vendor,device_type,hostname,private_mac,first_seen,last_seen FROM devices ORDER BY last_seen DESC LIMIT 4096")?;
    let rows=s.query_map([],|r|Ok(json!({"ip":r.get::<_,String>(0)?,"mac":r.get::<_,Option<String>>(1)?,"vendor":r.get::<_,Option<String>>(2)?,"device_type":r.get::<_,Option<String>>(3)?,"hostname":r.get::<_,Option<String>>(4)?,"private_mac":r.get::<_,Option<i64>>(5)?.unwrap_or(0)!=0,"first_seen":r.get::<_,Option<String>>(6)?,"last_seen":r.get::<_,Option<String>>(7)?,"online":false})))?.collect();
    rows
}
pub fn flush(c: &mut Connection, p: &Pending) -> rusqlite::Result<()> {
    let tx = c.transaction()?;
    {
        let mut traffic=tx.prepare_cached("INSERT INTO traffic(minute,category,packets,bytes) VALUES(?1,?2,?3,?4) ON CONFLICT(minute,category) DO UPDATE SET packets=packets+excluded.packets,bytes=bytes+excluded.bytes")?;
        for ((minute, category), (packets, bytes)) in &p.traffic {
            traffic.execute(params![minute, category, *packets as i64, *bytes as i64])?;
        }
        let mut hist=tx.prepare_cached("INSERT INTO history(minute,dim,key,packets,bytes) VALUES(?1,?2,?3,?4,?5) ON CONFLICT(minute,dim,key) DO UPDATE SET packets=packets+excluded.packets,bytes=bytes+excluded.bytes")?;
        for ((minute, dim, key), (packets, bytes)) in &p.history {
            hist.execute(params![minute, dim, key, *packets as i64, *bytes as i64])?;
        }
        let mut alert=tx.prepare_cached("INSERT OR IGNORE INTO alerts_log(id,ts,type,severity,message,node_id,details) VALUES(?1,?2,?3,?4,?5,?6,?7)")?;
        for a in &p.alerts {
            alert.execute(params![
                a["id"].as_str(),
                a["timestamp"].as_str(),
                a["type"].as_str(),
                a["severity"].as_str(),
                a["message"].as_str(),
                a["node_id"].as_str(),
                a["details"].to_string()
            ])?;
        }
        let mut device=tx.prepare_cached("INSERT INTO devices(ip,mac,vendor,device_type,hostname,private_mac,first_seen,last_seen) VALUES(?1,?2,?3,?4,?5,?6,?7,?8) ON CONFLICT(ip) DO UPDATE SET mac=COALESCE(excluded.mac,devices.mac),vendor=COALESCE(excluded.vendor,devices.vendor),device_type=COALESCE(excluded.device_type,devices.device_type),hostname=COALESCE(excluded.hostname,devices.hostname),private_mac=excluded.private_mac,last_seen=excluded.last_seen")?;
        for (ip, d) in &p.devices {
            device.execute(params![
                ip,
                d["mac"].as_str(),
                d["vendor"].as_str(),
                d["device_type"].as_str(),
                d["hostname"].as_str(),
                d["private_mac"] == true,
                d["first_seen"].as_str(),
                d["last_seen"].as_str()
            ])?;
        }
    }
    tx.commit()
}
pub fn cleanup(c: &mut Connection) -> rusqlite::Result<()> {
    let cutoff = (chrono::Utc::now() - chrono::Duration::hours(24))
        .format("%Y-%m-%dT%H:%M")
        .to_string();
    let tx = c.transaction()?;
    for table in ["traffic", "history"] {
        tx.execute(&format!("DELETE FROM {table} WHERE minute < ?1"), [&cutoff])?;
    }
    // Preserve the original alert log; do not silently discard old findings.
    tx.commit()
}
pub fn timeline(c: &Connection, minutes: u32) -> rusqlite::Result<Value> {
    let cutoff = (chrono::Utc::now() - chrono::Duration::minutes(minutes.clamp(1, 10080) as i64))
        .format("%Y-%m-%dT%H:%M")
        .to_string();
    let mut s = c.prepare(
        "WITH t AS (SELECT minute,SUM(packets) AS packets,SUM(bytes) AS bytes FROM traffic WHERE minute>=?1 GROUP BY minute), a AS (SELECT substr(ts,1,16) AS minute,COUNT(*) AS alerts FROM alerts_log WHERE ts>=?1 GROUP BY 1) SELECT t.minute,t.packets,t.bytes,COALESCE(a.alerts,0) FROM t LEFT JOIN a USING(minute) ORDER BY t.minute",
    )?;
    let rows=s.query_map([cutoff],|r|Ok(json!({"minute":r.get::<_,String>(0)?,"packets":r.get::<_,i64>(1)?,"bytes":r.get::<_,i64>(2)?,"alerts":r.get::<_,i64>(3)?})))?.collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(json!({"timeline":rows}))
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn legacy_device_with_null_private_mac_loads() {
        let c = Connection::open_in_memory().unwrap();
        c.execute_batch("CREATE TABLE devices(ip TEXT PRIMARY KEY,mac TEXT,vendor TEXT,device_type TEXT,hostname TEXT,private_mac INTEGER,first_seen TEXT,last_seen TEXT); INSERT INTO devices(ip,private_mac)VALUES('192.168.1.25',NULL);").unwrap();
        let values = devices(&c).unwrap();
        assert_eq!(values.len(), 1);
        assert_eq!(values[0]["private_mac"], false);
        assert_eq!(values[0]["online"], false);
    }
    #[test]
    fn atomic_accumulators_and_alert_roundtrip() {
        let dir = std::env::temp_dir().join(format!("genyra-storage-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let mut c = open(&dir).unwrap();
        let mut p = Pending::default();
        p.traffic
            .insert(("2099-01-01T00:00".into(), "safe".into()), (2, 300));
        p.history.insert(
            ("2099-01-01T00:00".into(), "host".into(), "8.8.8.8".into()),
            (2, 300),
        );
        p.alerts.push(json!({"id":"test","timestamp":"2099-01-01T00:00:00Z","type":"NEW_HOST","severity":"info","message":"test","node_id":"8.8.8.8","details":{"ok":true}}));
        flush(&mut c, &p).unwrap();
        flush(&mut c, &p).unwrap();
        assert_eq!(alerts(&c).unwrap().len(), 1);
        assert_eq!(alerts(&c).unwrap()[0]["details"]["ok"], true);
        assert_eq!(timeline(&c, 60).unwrap()["timeline"][0]["bytes"], 600);
        drop(c);
        std::fs::remove_dir_all(dir).unwrap();
    }
}
