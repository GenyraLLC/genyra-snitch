use crate::{
    web::{bad, ApiResult},
    App,
};
use serde_json::{json, Value};
use std::{
    collections::HashMap,
    fs,
    io::{Read, Seek, SeekFrom},
    os::fd::{AsRawFd, FromRawFd},
    time::Duration,
};

pub fn hollow(pid: u32) -> Value {
    let result = (|| -> Result<Value, String> {
        let exe = fs::read_link(format!("/proc/{pid}/exe")).map_err(|e| e.to_string())?;
        let maps = fs::read_to_string(format!("/proc/{pid}/maps")).map_err(|e| e.to_string())?;
        let mut mem = fs::File::open(format!("/proc/{pid}/mem"))
            .map_err(|e| format!("Process-memory access denied (ptrace/Yama): {e}"))?;
        let mut disk = fs::File::open(&exe).map_err(|e| e.to_string())?;
        let mut compared = 0;
        let mut mismatches = Vec::new();
        for line in maps.lines().take(50000) {
            let f: Vec<_> = line.split_whitespace().collect();
            if f.len() < 6
                || f[1].contains('w')
                || !f[1].contains('r')
                || f[5] != exe.to_string_lossy()
            {
                continue;
            }
            let Some((start, end)) = f[0].split_once('-').and_then(|(s, e)| {
                Some((
                    u64::from_str_radix(s, 16).ok()?,
                    u64::from_str_radix(e, 16).ok()?,
                ))
            }) else {
                continue;
            };
            let Ok(offset) = u64::from_str_radix(f[2], 16) else {
                continue;
            };
            let count = (end - start)
                .min(1024 * 1024)
                .min(8 * 1024 * 1024 - compared) as usize;
            if count == 0 {
                break;
            }
            mem.seek(SeekFrom::Start(start))
                .map_err(|e| e.to_string())?;
            disk.seek(SeekFrom::Start(offset))
                .map_err(|e| e.to_string())?;
            let mut memory = vec![0; count];
            let mut file = vec![0; count];
            mem.read_exact(&mut memory).map_err(|e| e.to_string())?;
            disk.read_exact(&mut file).map_err(|e| e.to_string())?;
            compared += count as u64;
            for (i, (m, d)) in memory.chunks(4096).zip(file.chunks(4096)).enumerate() {
                if m != d && mismatches.len() < 16 {
                    mismatches.push(json!({"vaddr":format!("0x{:x}",start+i as u64*4096),"file_off":format!("0x{:x}",offset+i as u64*4096),"size":m.len()}));
                }
            }
        }
        if compared == 0 {
            return Err("No readable file-backed executable regions".into());
        }
        Ok(
            json!({"ok":true,"pid":pid,"exe":exe,"matched_bytes":compared,"mismatches":mismatches,"note":"Read-only comparison; relocations or debugger breakpoints may also differ."}),
        )
    })();
    result.unwrap_or_else(|e| json!({"ok":false,"pid":pid,"error":e}))
}
pub fn perf(pid: u32, seconds: f64) -> Value {
    let result = (|| -> Result<Value, String> {
        let seconds = seconds.clamp(0.2, 10.);
        let mut fds = Vec::new();
        for (kind, config) in [(0u32, 0u64), (0, 1), (0, 3), (1, 1)] {
            let mut attr = [0u8; 128];
            attr[0..4].copy_from_slice(&kind.to_ne_bytes());
            attr[4..8].copy_from_slice(&128u32.to_ne_bytes());
            attr[8..16].copy_from_slice(&config.to_ne_bytes());
            attr[40..48].copy_from_slice(&1u64.to_ne_bytes());
            let fd = unsafe {
                libc::syscall(
                    libc::SYS_perf_event_open,
                    attr.as_ptr(),
                    pid as libc::pid_t,
                    -1i32,
                    -1i32,
                    8u64,
                )
            };
            if fd < 0 {
                return Err(std::io::Error::last_os_error().to_string());
            }
            fds.push(unsafe { fs::File::from_raw_fd(fd as i32) });
        }
        for fd in &fds {
            if unsafe { libc::ioctl(fd.as_raw_fd(), 0x2400, 0) } < 0 {
                return Err(std::io::Error::last_os_error().to_string());
            }
        }
        std::thread::sleep(Duration::from_secs_f64(seconds));
        let mut values = Vec::new();
        for fd in &mut fds {
            unsafe {
                libc::ioctl(fd.as_raw_fd(), 0x2401, 0);
            };
            let mut bytes = [0; 8];
            fd.read_exact(&mut bytes).map_err(|e| e.to_string())?;
            values.push(u64::from_ne_bytes(bytes));
        }
        let ms = (values[3] as f64 / 1e6).max(1.);
        Ok(
            json!({"ok":true,"pid":pid,"window_s":seconds,"instructions":values[1],"instr_per_s":values[1]as f64/ms*1000.,"cache_miss_per_s":values[2]as f64/ms*1000.,"ipc":values[1]as f64/values[0].max(1)as f64,"cpu_ms":ms}),
        )
    })();
    result.unwrap_or_else(|e| json!({"ok":false,"pid":pid,"error":e}))
}
pub fn export(a: &App, q: &HashMap<String, String>) -> ApiResult {
    let process = q.get("process");
    let ip = q.get("ip");
    let mut processes = Vec::new();
    if let Some(name) = process {
        if let Ok(entries) = fs::read_dir("/proc") {
            for entry in entries.flatten() {
                let Ok(pid) = entry.file_name().to_string_lossy().parse::<u32>() else {
                    continue;
                };
                let pname = fs::read_to_string(entry.path().join("comm")).unwrap_or_default();
                if pname.trim() != name {
                    continue;
                }
                let exe = fs::read_link(entry.path().join("exe")).ok();
                let cmdline = fs::read(entry.path().join("cmdline"))
                    .ok()
                    .map(|b| {
                        String::from_utf8_lossy(&b)
                            .split('\0')
                            .filter(|s| !s.is_empty())
                            .take(64)
                            .map(|s| s.chars().take(4096).collect::<String>())
                            .collect::<Vec<_>>()
                    })
                    .unwrap_or_default();
                let mut parents = Vec::new();
                let mut cur = pid;
                for _ in 0..8 {
                    let Some(ppid) = fs::read_to_string(format!("/proc/{cur}/stat"))
                        .ok()
                        .and_then(|s| {
                            s.rsplit_once(')')
                                .and_then(|(_, s)| s.split_whitespace().nth(1))
                                .and_then(|s| s.parse::<u32>().ok())
                        })
                    else {
                        break;
                    };
                    if ppid == 0 {
                        break;
                    }
                    parents.push(json!({"pid":ppid,"name":fs::read_to_string(format!("/proc/{ppid}/comm")).unwrap_or_default().trim()}));
                    cur = ppid;
                }
                let hash = exe
                    .as_ref()
                    .and_then(|p| a.integrity.lock().unwrap().hash_file(&p.to_string_lossy()));
                processes.push(json!({"pid":pid,"name":name,"exe":exe,"sha256":hash,"cmdline":cmdline,"parents":parents}));
                if processes.len() >= 256 {
                    break;
                }
            }
        }
    }
    let c = a.db.lock().unwrap();
    let rows = crate::storage::alerts_limit(&c, 500).map_err(|e| bad(e.to_string()))?;
    let alerts: Vec<_> = rows
        .into_iter()
        .filter(|alert| {
            process.is_none() && ip.is_none()
                || process.is_some_and(|p| alert.to_string().contains(p))
                || ip.is_some_and(|ip| alert["node_id"] == *ip)
        })
        .collect();
    let mut history = json!({});
    for (dim, key) in [("host", ip), ("process", process)] {
        if let Some(key) = key {
            let cutoff = (chrono::Utc::now() - chrono::Duration::hours(24))
                .format("%Y-%m-%dT%H:%M")
                .to_string();
            let mut stmt=c.prepare("SELECT minute,packets,bytes FROM history WHERE dim=?1 AND key=?2 AND minute>=?3 ORDER BY minute").map_err(|e|bad(e.to_string()))?;
            let rows=stmt.query_map(rusqlite::params![dim,key,cutoff],|r|Ok(json!({"minute":r.get::<_,String>(0)?,"packets":r.get::<_,i64>(1)?,"bytes":r.get::<_,i64>(2)?}))).map_err(|e|bad(e.to_string()))?.collect::<rusqlite::Result<Vec<_>>>().map_err(|e|bad(e.to_string()))?;
            history[dim] = json!(rows);
        }
    }
    drop(c);
    let geo = ip.and_then(|ip| a.engine.lock().unwrap().nodes.get(ip).map(|n| json!(n)));
    let bundle = json!({"filter_ip":ip,"generated_at":chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis,true),"version":env!("CARGO_PKG_VERSION"),"host":fs::read_to_string("/etc/hostname").unwrap_or_default().trim(),"processes":processes,"alerts":alerts,"history":history,"geo":geo});
    match q.get("format").map(String::as_str).unwrap_or("json") {
        "json" => Ok(bundle),
        "csv" => Ok(raw(
            "text/csv; charset=utf-8",
            "snitch-forensics.csv",
            csv(&bundle),
        )),
        "ecs" => Ok(raw(
            "application/x-ndjson",
            "snitch-forensics.ndjson",
            ecs(&bundle),
        )),
        "stix" => Ok(stix(&bundle)),
        _ => Err(bad("Unknown export format")),
    }
}
pub fn raw(mime: &str, name: &str, body: String) -> Value {
    json!({"_content_type":mime,"_filename":name,"_body":body})
}
fn text(value: &Value) -> String {
    if value.is_null() {
        String::new()
    } else {
        value
            .as_str()
            .map(str::to_string)
            .unwrap_or_else(|| value.to_string())
    }
}
fn csv(bundle: &Value) -> String {
    fn row(out: &mut String, fields: &[String]) {
        out.push_str(
            &fields
                .iter()
                .map(|s| format!("\"{}\"", s.replace('"', "\"\"")))
                .collect::<Vec<_>>()
                .join(","),
        );
        out.push_str("\r\n");
    }
    let mut out = "section,field,value\r\n".to_string();
    for field in ["generated_at", "version", "host"] {
        row(
            &mut out,
            &["meta".into(), field.into(), text(&bundle[field])],
        );
    }
    for p in bundle["processes"].as_array().into_iter().flatten() {
        for field in ["pid", "name", "exe", "sha256", "cmdline", "started"] {
            let v = if let Some(values) = p[field].as_array() {
                values.iter().map(text).collect::<Vec<_>>().join(" ")
            } else {
                text(&p[field])
            };
            row(&mut out, &["process".into(), field.into(), v]);
        }
        for parent in p["parents"].as_array().into_iter().flatten() {
            row(
                &mut out,
                &[
                    "process".into(),
                    "parent".into(),
                    format!("{} (pid {})", text(&parent["name"]), text(&parent["pid"])),
                ],
            );
        }
    }
    if let Some(history) = bundle["history"].as_object() {
        for (section, rows) in history {
            for r in rows.as_array().into_iter().flatten() {
                row(
                    &mut out,
                    &[
                        format!("history_{section}"),
                        text(r.get("bucket").unwrap_or(&r["minute"])),
                        r.to_string(),
                    ],
                );
            }
        }
    }
    for alert in bundle["alerts"].as_array().into_iter().flatten() {
        row(
            &mut out,
            &[
                "alert".into(),
                text(&alert["type"]),
                text(&alert["message"]),
            ],
        );
    }
    out
}
fn ecs(bundle: &Value) -> String {
    let base = json!({"ecs":{"version":"8.11"},"observer":{"vendor":"Genyra LLC","product":"Genyra Snitch","version":bundle["version"],"type":"firewall"},"host":{"name":bundle["host"]}});
    let mut out = String::new();
    for a in bundle["alerts"].as_array().into_iter().flatten() {
        let mut ev = base.clone();
        let d = &a["details"];
        ev["@timestamp"] = a
            .get("timestamp")
            .filter(|v| !v.is_null())
            .unwrap_or(&bundle["generated_at"])
            .clone();
        ev["event"] = json!({"kind":"alert","category":["network"],"type":["indicator"],"dataset":"snitch.alerts","action":a["type"],"severity":if a["severity"]=="critical"{80}else if a["severity"]=="warning"{50}else{21}});
        let dest = d["ip"].as_str().or_else(|| a["node_id"].as_str());
        if let Some(ip) = dest.filter(|v| !v.is_empty()) {
            ev["destination"] = json!({"ip":ip});
            if !d["port"].is_null() {
                ev["destination"]["port"] = d["port"].clone();
            }
        }
        if !d["process"].is_null() {
            ev["process"] = json!({"name":d["process"]});
            if !d["pid"].is_null() {
                ev["process"]["pid"] = d["pid"].clone();
            }
        }
        ev["message"] = a["message"].clone();
        ev["rule"] = json!({"name":a["type"]});
        out.push_str(&ev.to_string());
        out.push('\n');
    }
    for p in bundle["processes"].as_array().into_iter().flatten() {
        let mut ev = base.clone();
        ev["@timestamp"] = bundle["generated_at"].clone();
        ev["event"] = json!({"kind":"event","category":["process"],"type":["info"],"dataset":"snitch.forensics"});
        ev["process"] = json!({"name":p["name"],"pid":p["pid"],"executable":p["exe"],"command_line":p["cmdline"].as_array().into_iter().flatten().map(text).collect::<Vec<_>>().join(" ")});
        if !p["sha256"].is_null() {
            ev["file"] = json!({"hash":{"sha256":p["sha256"]},"path":p["exe"]});
        }
        if let Some(parent) = p["parents"].as_array().and_then(|p| p.first()) {
            ev["process"]["parent"] = json!({"name":parent["name"],"pid":parent["pid"]});
        }
        out.push_str(&ev.to_string());
        out.push('\n');
    }
    out
}
fn stix(bundle: &Value) -> Value {
    let stamp = &bundle["generated_at"];
    let mut objects = vec![
        json!({"type":"identity","spec_version":"2.1","id":format!("identity--{}",uuid::Uuid::new_v4()),"created":stamp,"modified":stamp,"name":"Genyra Snitch local forensics export","identity_class":"system"}),
    ];
    let mut seen = std::collections::HashSet::new();
    for a in bundle["alerts"].as_array().into_iter().flatten() {
        if let Some(ip) = a["node_id"]
            .as_str()
            .filter(|s| s.parse::<std::net::IpAddr>().is_ok())
        {
            if seen.insert(ip) {
                let kind = if ip.contains(':') {
                    "ipv6-addr"
                } else {
                    "ipv4-addr"
                };
                objects.push(json!({"type":"indicator","spec_version":"2.1","id":format!("indicator--{}",uuid::Uuid::new_v4()),"created":stamp,"modified":stamp,"name":format!("Genyra Snitch alert: {} → {ip}",text(&a["type"])),"pattern":format!("[{kind}:value = '{ip}']"),"pattern_type":"stix","valid_from":stamp,"description":text(&a["message"]).chars().take(500).collect::<String>()}));
            }
        }
    }
    if let Some(ip) = bundle["filter_ip"]
        .as_str()
        .filter(|s| s.parse::<std::net::IpAddr>().is_ok())
    {
        objects.push(json!({"type":"observed-data","spec_version":"2.1","id":format!("observed-data--{}",uuid::Uuid::new_v4()),"created":stamp,"modified":stamp,"first_observed":stamp,"last_observed":stamp,"number_observed":1,"objects":{"0":{"type":if ip.contains(':'){"ipv6-addr"}else{"ipv4-addr"},"value":ip}}}));
    }
    for p in bundle["processes"].as_array().into_iter().flatten() {
        if let Some(hash) = p["sha256"]
            .as_str()
            .filter(|h| h.len() == 64 && h.bytes().all(|b| b.is_ascii_hexdigit()))
        {
            objects.push(json!({"type":"indicator","spec_version":"2.1","id":format!("indicator--{}",uuid::Uuid::new_v4()),"created":stamp,"modified":stamp,"name":format!("Genyra Snitch process: {}",text(&p["name"])),"pattern":format!("[file:hashes.'SHA-256' = '{hash}']"),"pattern_type":"stix","valid_from":stamp}));
        }
    }
    json!({"type":"bundle","id":format!("bundle--{}",uuid::Uuid::new_v4()),"objects":objects})
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn csv_escapes_quotes_and_embedded_lines() {
        let s = csv(&json!({"alerts":[{"message":"hello,\"world\"\nnext","timestamp":"now"}]}));
        assert!(s.contains("\"hello,\"\"world\"\"\nnext\""));
    }
    #[test]
    fn stix_has_valid_ip_patterns() {
        let v = stix(
            &json!({"generated_at":"2026-01-01T00:00:00Z","alerts":[{"node_id":"8.8.8.8","type":"NEW_HOST"},{"node_id":"not-an-ip"}]}),
        );
        assert_eq!(v["objects"].as_array().unwrap().len(), 2);
        assert_eq!(v["objects"][1]["pattern"], "[ipv4-addr:value = '8.8.8.8']");
    }
}
