use crate::{
    integrity,
    web::{bad, error, save, ApiResult},
    App,
};
use axum::http::{Method, StatusCode};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
#[cfg(unix)]
use std::os::unix::process::CommandExt;
#[cfg(unix)]
use std::process::{Command, Stdio};
use std::{
    collections::HashMap,
    fs,
    io::Read,
    net::IpAddr,
    time::{Duration, Instant},
};
#[cfg(target_os = "linux")]
use std::{io::Write, net::ToSocketAddrs};

type CompiledCondition = (Value, Option<regex::Regex>);
pub struct Rules {
    entries: Vec<(Value, Vec<CompiledCondition>)>,
    pub invalid: Vec<String>,
}
impl Rules {
    pub fn new(value: &Value) -> Self {
        let mut entries = Vec::new();
        let mut invalid = Vec::new();
        for r in value.as_array().into_iter().flatten().take(64) {
            if let Err(error) = validate_rule(r) {
                invalid.push(format!(
                    "{}: {error}",
                    r["id"].as_str().unwrap_or("unnamed")
                ));
                continue;
            }
            let clauses = r["conds"]
                .as_array()
                .cloned()
                .unwrap_or_else(|| vec![r.clone()]);
            let compiled = clauses
                .into_iter()
                .map(|c| {
                    let re = if c["op"] == "regex" {
                        regex::Regex::new(c["value"].as_str().unwrap_or("")).ok()
                    } else {
                        None
                    };
                    (c, re)
                })
                .collect();
            entries.push((r.clone(), compiled));
        }
        Self { entries, invalid }
    }
    pub fn matches(&self, fields: &Value) -> Vec<Value> {
        self.entries
            .iter()
            .filter(|(r, conds)| {
                r["enabled"] != false && conds.iter().all(|(c, re)| matches_clause(c, re, fields))
            })
            .map(|(r, _)| r.clone())
            .collect()
    }
}
fn matches_clause(c: &Value, re: &Option<regex::Regex>, fields: &Value) -> bool {
    let field = &fields[c["field"].as_str().unwrap_or("")];
    let field = field
        .as_str()
        .map(str::to_string)
        .unwrap_or_else(|| field.to_string());
    let value = c["value"]
        .as_str()
        .map(str::to_string)
        .unwrap_or_else(|| c["value"].to_string());
    match c["op"].as_str().unwrap_or("") {
        "eq" => field.eq_ignore_ascii_case(&value),
        "ne" => !field.eq_ignore_ascii_case(&value),
        "contains" => field.to_lowercase().contains(&value.to_lowercase()),
        "regex" => re.as_ref().is_some_and(|r| r.is_match(&field)),
        "gt" => field
            .parse::<f64>()
            .ok()
            .zip(value.parse().ok())
            .is_some_and(|(f, v)| f > v),
        "lt" => field
            .parse::<f64>()
            .ok()
            .zip(value.parse().ok())
            .is_some_and(|(f, v)| f < v),
        "cidr" => value
            .parse::<ipnet::IpNet>()
            .ok()
            .zip(field.parse::<IpAddr>().ok())
            .is_some_and(|(net, ip)| net.contains(&ip)),
        _ => false,
    }
}
fn validate_clause(v: &Value) -> Result<(), String> {
    if ![
        "remote_ip",
        "host",
        "process_name",
        "cmdline",
        "parent_name",
        "remote_port",
        "protocol",
        "direction",
        "size",
        "asn",
        "country",
    ]
    .contains(&v["field"].as_str().unwrap_or(""))
    {
        return Err("Unknown rule field".into());
    }
    let op = v["op"].as_str().unwrap_or("");
    if !["eq", "ne", "contains", "regex", "gt", "lt", "cidr"].contains(&op) {
        return Err("Unknown rule operator".into());
    }
    let value = v["value"]
        .as_str()
        .map(str::to_string)
        .unwrap_or_else(|| v["value"].to_string());
    if value.len() > 200 {
        return Err("Rule value exceeds 200 characters".into());
    }
    if op == "regex" {
        regex::RegexBuilder::new(&value)
            .size_limit(256 * 1024)
            .build()
            .map_err(|e| e.to_string())?;
    }
    if op == "cidr" {
        value.parse::<ipnet::IpNet>().map_err(|e| e.to_string())?;
    }
    Ok(())
}
fn validate_rule(v: &Value) -> Result<(), String> {
    if !["info", "warning", "critical"].contains(&v["severity"].as_str().unwrap_or("info")) {
        return Err("Invalid severity".into());
    }
    if !["alert", "block"].contains(&v["action"].as_str().unwrap_or("alert")) {
        return Err("Invalid action".into());
    }
    if let Some(clauses) = v["conds"].as_array() {
        if clauses.is_empty() || clauses.len() > 64 {
            return Err("Combined rules require 1..64 conditions".into());
        }
        for clause in clauses {
            validate_clause(clause)?;
        }
        Ok(())
    } else {
        validate_clause(v)
    }
}
fn config(a: &App) -> Value {
    a.engine.lock().unwrap().settings.clone()
}
pub fn api(
    a: &App,
    method: &Method,
    path: &str,
    q: &HashMap<String, String>,
    body: &Value,
) -> ApiResult {
    if crate::demo::enabled()
        && method == Method::POST
        && [
            "/processes/kill",
            "/processes/suspend",
            "/security/deep_inspect",
            "/security/sandbox",
            "/security/perf",
            "/security/hollow",
            "/security/integrity/check",
            "/security/ebpf/block",
            "/security/ebpf/isolate",
        ]
        .contains(&path)
    {
        return Err(bad("Process and kernel actions are disabled in demo mode"));
    }
    let get = method == Method::GET;
    let post = method == Method::POST;
    let delete = method == Method::DELETE;
    match (path, get, post) {
        ("/geo/download", _, true) => crate::enrichment::download_geo(a, body),
        ("/security/deep_inspect", _, true) => Ok(crate::deep::inspect(
            a,
            pid(body)?,
            body["seconds"].as_u64().unwrap_or(20),
        )),
        ("/security/ask", true, _) => Ok(a.ask.status(&config(a))),
        ("/security/ask/verdict", _, true) => {
            let ip = body["remote_ip"]
                .as_str()
                .ok_or_else(|| bad("remote_ip required"))?
                .parse::<IpAddr>()
                .map_err(|_| bad("Invalid remote_ip"))?;
            let port = body["remote_port"]
                .as_u64()
                .and_then(|n| u16::try_from(n).ok())
                .ok_or_else(|| bad("Invalid remote_port"))?;
            let proto = body["proto"].as_str().unwrap_or("TCP");
            if !["TCP", "UDP"].contains(&proto.to_uppercase().as_str()) {
                return Err(bad("Invalid protocol"));
            }
            let decided = a.ask.decide(ip, port, proto, body["allow"] == true);
            let mut persisted = Value::Null;
            if body["permanent"] == true {
                if body["allow"] == true {
                    let mut ips = config(a)["whitelisted_ips"]
                        .as_array()
                        .cloned()
                        .unwrap_or_default();
                    if !ips
                        .iter()
                        .any(|s| s.as_str().and_then(|s| s.parse::<IpAddr>().ok()) == Some(ip))
                    {
                        ips.push(json!(ip));
                    }
                    save(a, "whitelisted_ips", json!(ips))?;
                    persisted = json!("whitelisted");
                } else {
                    add_firewall_rule(
                        a,
                        &json!({"kind":"ip","value":ip.to_string(),"action":"block"}),
                    )?;
                    persisted = json!("firewall_rule");
                }
            }
            Ok(
                json!({"ok":decided,"persisted":persisted,"note":if decided{"verdict applied"}else{"flow already timed out — OS policy applied"}}),
            )
        }
        ("/security/ebpf", true, _) => Ok(a.kernel.probe_status()),
        ("/security/ebpf_enforce", true, _) => Ok(a.kernel.enforcer_status()),
        ("/security/ebpf/block", _, true) => {
            let ip = body["ip"]
                .as_str()
                .ok_or_else(|| bad("IP required"))?
                .parse::<IpAddr>()
                .map_err(|_| bad("Invalid IP"))?;
            let result = a.kernel.block(ip);
            Ok(
                json!({"ok":result.is_ok(),"applied":result.is_ok(),"error":result.err(),"scope":"processes in the Genyra Snitch cgroup","status":a.kernel.enforcer_status()}),
            )
        }
        ("/security/ebpf/isolate", _, true) => {
            let pid = pid(body)?;
            let result = a.kernel.isolate(pid);
            Ok(
                json!({"ok":result.is_ok(),"applied":result.is_ok(),"pid":pid,"error":result.err(),"scope":"cgroup-scoped blocked-destination policy","status":a.kernel.enforcer_status()}),
            )
        }
        ("/security/hollow", _, true) => Ok(crate::forensics::hollow(pid(body)?)),
        ("/security/perf", _, true) => Ok(crate::forensics::perf(
            pid(body)?,
            body["seconds"].as_f64().unwrap_or(1.5),
        )),
        ("/security/integrity", true, _) => Ok(a
            .integrity
            .lock()
            .unwrap()
            .status(config(a)["integrity_watch"] != false)),
        ("/security/integrity/check", _, true) => {
            let pid = pid(body)?;
            let findings = a.integrity.lock().unwrap().check(pid, true);
            record_findings(a, &findings);
            Ok(json!({"pid":pid,"findings":findings}))
        }
        ("/processes/kill", _, true) | ("/processes/suspend", _, true) => {
            let pid = pid(body)?;
            crate::platform::control_process(pid, path.ends_with("kill")).map_err(bad)
        }
        ("/alerts/rules/sigma", _, true) => {
            let (imported, mut skipped) =
                crate::rules::sigma(body["yaml"].as_str().unwrap_or("")).map_err(bad)?;
            let mut current = config(a)["custom_rules"]
                .as_array()
                .cloned()
                .unwrap_or_default();
            let mut added = Vec::new();
            for mut rule in imported {
                if current.len() >= 64 {
                    skipped.push("Custom rule capacity reached".into());
                    break;
                }
                if let Err(e) = validate_rule(&rule) {
                    skipped.push(e);
                    continue;
                }
                rule["id"] = json!(uuid::Uuid::new_v4().to_string());
                current.push(rule.clone());
                added.push(rule);
            }
            save(a, "custom_rules", json!(current))?;
            Ok(json!({"ok":true,"imported":added.len(),"rules":added,"skipped":skipped}))
        }
        ("/alerts/rules/yaral", true, _) => Ok(crate::forensics::raw(
            "text/plain; charset=utf-8",
            "genyra-snitch.yar",
            crate::rules::yaral(&config(a)["custom_rules"]),
        )),
        ("/alerts/rules", true, _) => Ok(
            json!({"rules":config(a).get("custom_rules").cloned().unwrap_or(json!([])),"fields":["remote_ip","host","process_name","cmdline","parent_name","remote_port","protocol","direction","size","asn","country"],"ops":["eq","ne","contains","regex","gt","lt","cidr"]}),
        ),
        ("/alerts/rules", _, true) => {
            validate_rule(body).map_err(bad)?;
            let mut rules = config(a)["custom_rules"]
                .as_array()
                .cloned()
                .unwrap_or_default();
            if rules.len() >= 64 {
                return Err(bad("Custom rule limit reached"));
            }
            let mut rule = body.clone();
            rule["id"] = json!(uuid::Uuid::new_v4().to_string());
            rule["enabled"] = json!(true);
            if rule["severity"].is_null() {
                rule["severity"] = json!("info");
            }
            if rule["action"].is_null() {
                rule["action"] = json!("alert");
            }
            rules.push(rule.clone());
            save(a, "custom_rules", json!(rules))?;
            Ok(json!({"ok":true,"rule":rule}))
        }
        _ if path.starts_with("/alerts/rules/") && (delete || post) && !path.ends_with("sigma") => {
            let rest = path.trim_start_matches("/alerts/rules/");
            let id = rest.trim_end_matches("/toggle");
            let mut rules = config(a)["custom_rules"]
                .as_array()
                .cloned()
                .unwrap_or_default();
            let old = rules.len();
            if delete {
                rules.retain(|r| r["id"] != id);
                if old == rules.len() {
                    return Err(error(StatusCode::NOT_FOUND, "Rule not found"));
                }
            } else {
                let r = rules
                    .iter_mut()
                    .find(|r| r["id"] == id)
                    .ok_or_else(|| error(StatusCode::NOT_FOUND, "Rule not found"))?;
                r["enabled"] = json!(body["enabled"] == true);
            }
            save(a, "custom_rules", json!(rules))?;
            Ok(json!({"ok":true}))
        }
        ("/firewall/status", true, _) => Ok(firewall_status(a)),
        ("/firewall/rules", true, _) => {
            let s = config(a);
            Ok(
                json!({"rules":firewall_rules(a),"lockdown":s["firewall_lockdown"]==true,"supported":command_exists("nft")||command_exists("iptables")}),
            )
        }
        ("/firewall/rules", _, true) => add_firewall_rule(a, body),
        _ if path.starts_with("/firewall/rules/") && (delete || post) => {
            let rest = path.trim_start_matches("/firewall/rules/");
            let id = rest.trim_end_matches("/toggle");
            let mut rules = config(a)["firewall_rules"]
                .as_array()
                .cloned()
                .unwrap_or_default();
            let index = rules
                .iter()
                .position(|r| r["id"] == id)
                .ok_or_else(|| error(StatusCode::NOT_FOUND, "Rule not found"))?;
            if delete {
                rules.remove(index);
            } else {
                rules[index]["enabled"] = json!(body["enabled"] == true);
            }
            save(a, "firewall_rules", json!(rules))?;
            let result = sync_firewall(a);
            Ok(json!({"ok":result.is_ok(),"error":result.err(),"rules":rules}))
        }
        ("/firewall/lockdown", _, true) => {
            let previous = config(a)["firewall_lockdown"] == true;
            save(a, "firewall_lockdown", json!(body["on"] == true))?;
            if let Err(e) = sync_firewall(a) {
                save(a, "firewall_lockdown", json!(previous))?;
                return Ok(json!({"ok":false,"lockdown":previous,"error":e}));
            }
            Ok(json!({"ok":true,"lockdown":body["on"]==true,"error":null}))
        }
        ("/firewall/profiles", true, _) => {
            Ok(json!({"profiles":["balanced","permissive","strict"]}))
        }
        ("/firewall/profile", _, true) => profile(a, body),
        ("/firewall/blocklist", _, true) => blocklist(a, body),
        ("/security/ti", true, _) => Ok(ti_config(a)),
        ("/security/threat_check", _, true) => threat(a, body),
        ("/security/slm", true, _) => Ok(a.runtime.block_on(crate::slm::status(a))),
        ("/security/explain", true, _) | ("/security/explain", _, true) => {
            let kind = if get {
                q.get("type").map(String::as_str).unwrap_or("")
            } else {
                body["type"].as_str().unwrap_or("")
            }
            .to_uppercase();
            let explanations: Value =
                serde_json::from_str(include_str!("../resources/explanations.json")).unwrap();
            let mut result = explanations[&kind]
                .as_object()
                .cloned()
                .map(Value::Object)
                .ok_or_else(|| {
                    error(StatusCode::NOT_FOUND, "No explanation for this alert type")
                })?;
            result["type"] = json!(kind);
            if post {
                if let Some(llm) = a.runtime.block_on(crate::slm::enrich(
                    a,
                    &kind,
                    &body["detail"],
                    body["lang"].as_str().unwrap_or("en"),
                )) {
                    result["llm"] = json!(llm);
                }
            }
            Ok(result)
        }
        ("/security/audit", true, _) => Ok(audit(a)),
        ("/security/iocpack", true, _) => {
            Ok(ioc_pack(a, q.get("format").is_some_and(|s| s == "proof")))
        }
        ("/security/iocpack/import", _, true) => Ok(check_ioc(a, &body["pack"])),
        ("/ingest/enroll", _, true) => enroll(a, body),
        ("/ingest/agents", true, _) => Ok(
            json!({"agents":config(a)["agent_tokens"].as_object().into_iter().flatten().filter_map(|(_,v)|v["name"].as_str()).collect::<Vec<_>>()}),
        ),
        ("/ingest/revoke", _, true) => {
            let mut store = config(a)["agent_tokens"]
                .as_object()
                .cloned()
                .unwrap_or_default();
            store.retain(|_, v| v["name"] != body["name"]);
            save(a, "agent_tokens", json!(store))?;
            Ok(
                json!({"ok":true,"agents":store.values().map(|v|v["name"].clone()).collect::<Vec<_>>()}),
            )
        }
        ("/ingest/events", _, true) => ingest(a, body),
        ("/remote/ioc_sync", true, _) => Ok(crate::integrations::status(a)),
        ("/remote/ioc_sync", _, true) => Ok(a
            .runtime
            .block_on(crate::integrations::sync(a.clone(), ioc_pack(a, true)))),
        ("/remote/fleet", true, _) => Ok(a.runtime.block_on(crate::integrations::fleet(a.clone()))),
        ("/forensics/export", true, _) => crate::forensics::export(a, q),
        ("/security/sandbox", _, true) => sandbox(body),
        ("/security/sinkhole", true, _) => Ok(a.sinkhole.status()),
        _ => Err(error(
            StatusCode::NOT_FOUND,
            format!("Unknown endpoint: {method} {path}"),
        )),
    }
}
pub fn record_findings(a: &App, findings: &[Value]) {
    for finding in findings {
        let mut e = a.engine.lock().unwrap();
        e.alert(
            finding["type"].as_str().unwrap_or("INTEGRITY"),
            "",
            finding["severity"].as_str().unwrap_or("warning"),
            finding["detail"]
                .as_str()
                .unwrap_or("Integrity finding")
                .into(),
            finding.clone(),
        );
    }
}
fn pid(body: &Value) -> Result<u32, (StatusCode, String)> {
    let pid = body["pid"]
        .as_u64()
        .and_then(|n| u32::try_from(n).ok())
        .filter(|n| *n > 3 && *n != std::process::id() && *n <= i32::MAX as u32)
        .ok_or_else(|| bad("Refusing invalid or critical PID"))?;
    Ok(pid)
}
fn command_exists(name: &str) -> bool {
    std::env::var_os("PATH")
        .is_some_and(|path| std::env::split_paths(&path).any(|p| p.join(name).is_file()))
}
fn firewall_rules(a: &App) -> Value {
    let e = a.engine.lock().unwrap();
    let mut rules = e.settings["firewall_rules"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    for rule in &mut rules {
        rule["blocked_total"] = json!(e
            .blocked_counts
            .get(rule["id"].as_str().unwrap_or(""))
            .copied()
            .unwrap_or(0));
    }
    json!(rules)
}
fn firewall_status(a: &App) -> Value {
    let s = config(a);
    #[cfg(target_os = "linux")]
    let supported = command_exists("nft");
    #[cfg(not(target_os = "linux"))]
    let supported = crate::platform::firewall::supported();
    json!({"supported":supported,"platform":std::env::consts::OS,"demo":crate::demo::enabled(),"lockdown":s["firewall_lockdown"]==true,"rules":firewall_rules(a),"blocked_counts":a.engine.lock().unwrap().blocked_counts})
}
fn validate_firewall(body: &Value) -> Result<(), String> {
    let kind = body["kind"].as_str().unwrap_or("");
    let value = body["value"].as_str().unwrap_or("");
    if value.is_empty() || value.len() > 253 {
        return Err("Invalid rule value".into());
    }
    match kind {
        "ip" | "cidr" => {
            if value.parse::<IpAddr>().is_err() && value.parse::<ipnet::IpNet>().is_err() {
                return Err("Invalid IP or CIDR".into());
            }
        }
        "port" => {
            value
                .parse::<u16>()
                .ok()
                .filter(|p| *p > 0)
                .ok_or("Invalid port")?;
        }
        "domain" => {
            if !value
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b".-_".contains(&b))
            {
                return Err("Invalid domain".into());
            }
        }
        "process" => {
            if value.contains(['\n', '\r', '\0']) {
                return Err("Invalid process name".into());
            }
        }
        _ => return Err("Invalid rule kind".into()),
    }
    if !["block", "sinkhole", "throttle"].contains(&body["action"].as_str().unwrap_or("block")) {
        return Err("Invalid firewall action".into());
    }
    if body["action"] != "block"
        && !body["action"].is_null()
        && ["process", "port"].contains(&body["kind"].as_str().unwrap_or(""))
    {
        return Err("sinkhole/throttle is not meaningful for process or port rules".into());
    }
    if let Some(rate) = body.get("rate") {
        if !rate.as_u64().is_some_and(|r| (1..=10000000).contains(&r)) {
            return Err("rate must be 1..10000000 kbit/s".into());
        }
    }
    Ok(())
}
pub(crate) fn add_firewall_rule(a: &App, body: &Value) -> ApiResult {
    validate_firewall(body).map_err(bad)?;
    let mut rules = config(a)["firewall_rules"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    if rules.len() >= 5000 {
        return Err(bad("Firewall rule limit reached"));
    }
    let mut rule = body.clone();
    rule["id"] = json!(uuid::Uuid::new_v4().to_string());
    rule["enabled"] = json!(true);
    rule["created_at"] = json!(chrono::Utc::now().to_rfc3339());
    rule["applied"] = json!(false);
    if rule["action"].is_null() {
        rule["action"] = json!("block");
    }
    rules.push(rule.clone());
    save(a, "firewall_rules", json!(rules))?;
    let result = sync_firewall(a);
    rule["applied"] = json!(result.is_ok());
    rule["error"] = json!(result.err());
    if let Some(last) = rules.last_mut() {
        *last = rule.clone();
    }
    save(a, "firewall_rules", json!(rules))?;
    Ok(json!({"rule":rule,"rules":rules}))
}
#[cfg(not(target_os = "linux"))]
pub(crate) fn sync_firewall(a: &App) -> Result<(), String> {
    if crate::demo::enabled() {
        return Ok(());
    }
    crate::platform::firewall::sync(&config(a))
}
#[cfg(target_os = "linux")]
pub(crate) fn sync_firewall(a: &App) -> Result<(), String> {
    if crate::demo::enabled() {
        return Ok(());
    }
    // A dedicated nft table leaves unrelated host policy untouched. Atomic
    // nft transactions ensure a failed validation cannot partially apply.
    let s = config(a);
    let rules = s["firewall_rules"].as_array().cloned().unwrap_or_default();
    if !command_exists("nft") {
        return Err("nft executable unavailable".into());
    }
    let exists = Command::new("nft")
        .args(["list", "table", "inet", "genyra_snitch"])
        .output()
        .map_err(|e| e.to_string())?;
    let mut script = String::new();
    if exists.status.success() {
        script.push_str("delete table inet genyra_snitch\n");
    }
    script.push_str("add table inet genyra_snitch\nadd chain inet genyra_snitch output { type filter hook output priority 0; policy accept; }\nadd chain inet genyra_snitch sink_output { type nat hook output priority -100; policy accept; }\n");
    for rule in rules.iter().filter(|r| r["enabled"] != false) {
        validate_firewall(rule)?;
        let value = rule["value"].as_str().unwrap();
        let expressions = match rule["kind"].as_str().unwrap() {
            "ip" | "cidr" => vec![format!(
                "{} daddr {value}",
                if value.contains(':') { "ip6" } else { "ip" }
            )],
            "port" => vec![format!("meta l4proto {{ tcp, udp }} th dport {value}")],
            "domain" => (value, 0)
                .to_socket_addrs()
                .map_err(|e| e.to_string())?
                .take(32)
                .map(|sa| {
                    format!(
                        "{} daddr {}",
                        if sa.is_ipv6() { "ip6" } else { "ip" },
                        sa.ip()
                    )
                })
                .collect(),
            "process" => continue,
            _ => return Err("Unknown firewall rule kind".into()),
        };
        for expr in expressions {
            match rule["action"].as_str().unwrap_or("block") {
                "sinkhole" => {
                    let family = if expr.starts_with("ip6") { "ip6" } else { "ip" };
                    let local = if family == "ip6" { "::1" } else { "127.0.0.1" };
                    script.push_str(&format!(
                        "add rule inet genyra_snitch sink_output {expr} counter dnat {family} to {local}\n"
                    ));
                }
                "throttle" => {
                    let rate = rule["rate"].as_u64().unwrap_or(64).clamp(1, 10000000) * 125;
                    script.push_str(&format!("add rule inet genyra_snitch output {expr} limit rate over {rate} bytes/second burst {} bytes counter drop\n",rate.max(1500)));
                }
                _ => script.push_str(&format!(
                    "add rule inet genyra_snitch output {expr} counter drop\n"
                )),
            }
        }
    }
    if s["firewall_lockdown"] == true {
        for net in [
            "127.0.0.0/8",
            "10.0.0.0/8",
            "172.16.0.0/12",
            "192.168.0.0/16",
            "169.254.0.0/16",
        ] {
            script.push_str(&format!(
                "add rule inet genyra_snitch output ip daddr {net} return\n"
            ));
        }
        for net in ["::1/128", "fc00::/7", "fe80::/10"] {
            script.push_str(&format!(
                "add rule inet genyra_snitch output ip6 daddr {net} return\n"
            ));
        }
        script.push_str("add rule inet genyra_snitch output counter drop\n");
    }
    let mut child = Command::new("nft")
        .args(["-f", "-"])
        .stdin(Stdio::piped())
        .stderr(Stdio::piped())
        .stdout(Stdio::null())
        .spawn()
        .map_err(|e| e.to_string())?;
    child
        .stdin
        .take()
        .unwrap()
        .write_all(script.as_bytes())
        .map_err(|e| e.to_string())?;
    let output = child.wait_with_output().map_err(|e| e.to_string())?;
    if output.status.success() {
        a.kernel.sync_process_policy(&process_rule_names(&s))
    } else {
        Err(String::from_utf8_lossy(&output.stderr)
            .chars()
            .take(1000)
            .collect())
    }
}
pub(crate) fn process_rule_names(settings: &Value) -> std::collections::HashSet<String> {
    settings["firewall_rules"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|r| r["enabled"] != false && r["kind"] == "process")
        .filter_map(|r| r["value"].as_str().map(str::to_string))
        .collect()
}
/// Restore saved policy and refresh DNS-based rules, keeping process polling
/// separate from nft transactions so policy counters survive between refreshes.
pub fn policy_worker(a: App) {
    if crate::demo::enabled() {
        return;
    }
    let mut refreshed = Instant::now() - Duration::from_secs(601);
    while !a.stop.load(std::sync::atomic::Ordering::Relaxed) {
        let settings = config(&a);
        let names = process_rule_names(&settings);
        if let Err(error) = a.kernel.sync_process_policy(&names) {
            if refreshed.elapsed() >= Duration::from_secs(600) {
                eprintln!("Process firewall unavailable: {error}");
            }
        }
        if refreshed.elapsed() >= Duration::from_secs(600) {
            if settings["firewall_lockdown"] == true
                || settings["firewall_rules"]
                    .as_array()
                    .is_some_and(|r| r.iter().any(|r| r["enabled"] != false))
            {
                let _guard = a.mutations.lock().unwrap();
                if let Err(error) = sync_firewall(&a) {
                    eprintln!("Saved firewall policy could not be restored: {error}");
                }
            }
            refreshed = Instant::now();
        }
        crate::interruptible_sleep(&a.stop, Duration::from_secs(1));
    }
}
fn profile(a: &App, body: &Value) -> ApiResult {
    let name = body["name"].as_str().unwrap_or("");
    if !["balanced", "strict", "permissive"].contains(&name) {
        return Err(bad("Unknown profile"));
    }
    if name == "permissive" {
        save(a, "firewall_rules", json!([]))?;
    } else {
        for port in [25, 3333, 5555, 7777, 14444] {
            let exists = config(a)["firewall_rules"].as_array().is_some_and(|rules| {
                rules.iter().any(|r| {
                    r["kind"] == "port"
                        && r["value"].as_str().and_then(|s| s.parse::<u16>().ok()) == Some(port)
                })
            });
            if !exists {
                add_firewall_rule(
                    a,
                    &json!({"kind":"port","value":port.to_string(),"action":"block"}),
                )?;
            }
        }
    }
    save(a, "firewall_lockdown", json!(name == "strict"))?;
    let result = sync_firewall(a);
    Ok(
        json!({"ok":result.is_ok(),"error":result.err(),"rules":config(a)["firewall_rules"],"lockdown":config(a)["firewall_lockdown"],"profile":name}),
    )
}
fn network(a: &App, request: reqwest::RequestBuilder) -> Result<Value, String> {
    a.runtime.block_on(async {
        let mut response = request
            .send()
            .await
            .map_err(|e| e.to_string())?
            .error_for_status()
            .map_err(|e| e.to_string())?;
        let mut bytes = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(|e| e.to_string())? {
            if bytes.len() + chunk.len() > 2 * 1024 * 1024 {
                return Err("Response exceeds 2 MiB".into());
            }
            bytes.extend_from_slice(&chunk);
        }
        serde_json::from_slice(&bytes).map_err(|e| e.to_string())
    })
}
fn ti_config(a: &App) -> Value {
    let s = config(a);
    let provider = s["ti_provider"].as_str().unwrap_or("none");
    let key = s["ti_api_key"].as_str().unwrap_or("");
    json!({"enabled":provider!="none"&&!key.is_empty(),"provider":provider,"api_key_masked":if key.is_empty(){""}else{"…"},"cached":a.ti_cache.lock().unwrap().len()})
}
fn threat(a: &App, body: &Value) -> ApiResult {
    let s = config(a);
    let cfg = ti_config(a);
    let ip = body["ip"].as_str().ok_or_else(|| bad("IP required"))?;
    let ip: IpAddr = ip.parse().map_err(|_| bad("Invalid IP"))?;
    if cfg["enabled"] != true || crate::state::private(ip) {
        return Ok(json!({"verdict":{"ip":ip,"malicious":false,"enabled":false},"config":cfg}));
    }
    let key = s["ti_api_key"].as_str().unwrap_or("");
    let provider = s["ti_provider"].as_str().unwrap_or("none");
    let request = match provider {
        "abuseipdb" => a
            .http
            .get("https://api.abuseipdb.com/api/v2/check")
            .query(&[("ipAddress", ip.to_string()), ("maxAgeInDays", "90".into())])
            .header("Key", key),
        "otx" => a
            .http
            .get(format!(
                "https://otx.alienvault.com/api/v1/indicators/{}/{ip}/general",
                if ip.is_ipv4() { "IPv4" } else { "IPv6" }
            ))
            .header("X-OTX-API-KEY", key),
        "virustotal" => a
            .http
            .get(format!(
                "https://www.virustotal.com/api/v3/ip_addresses/{ip}"
            ))
            .header("x-apikey", key),
        _ => return Err(bad("Unknown threat provider")),
    };
    let cache_key = format!("{provider}:{}:{ip}", integrity::sha(key));
    if let Some((at, verdict)) = a.ti_cache.lock().unwrap().get(&cache_key) {
        if at.elapsed() < Duration::from_secs(3600) {
            return Ok(json!({"verdict":verdict,"config":cfg}));
        }
    }
    let result = network(a, request);
    let verdict = match result {
        Ok(v) => {
            let (score, malicious, suspicious, detail) = match provider {
                "abuseipdb" => {
                    let score = v["data"]["abuseConfidenceScore"].as_u64().unwrap_or(0);
                    (
                        score,
                        score >= 50,
                        score >= 25,
                        format!(
                            "confidence {score}%, {} reports",
                            v["data"]["totalReports"].as_u64().unwrap_or(0)
                        ),
                    )
                }
                "otx" => {
                    let score = v["pulse_info"]["count"].as_u64().unwrap_or(0);
                    (score, score >= 3, score >= 1, format!("{score} pulses"))
                }
                _ => {
                    let stats = &v["data"]["attributes"]["last_analysis_stats"];
                    let hits = stats["malicious"].as_u64().unwrap_or(0);
                    let suspicious = stats["suspicious"].as_u64().unwrap_or(0);
                    (
                        hits,
                        hits >= 3,
                        hits >= 1 || suspicious >= 2,
                        format!("{hits} malicious / {suspicious} suspicious engines"),
                    )
                }
            };
            json!({"ip":ip,"provider":provider,"score":score,"verdict":if malicious{"malicious"}else if suspicious{"suspicious"}else{"clean"},"malicious":malicious,"enabled":true,"detail":detail})
        }
        Err(_) => {
            json!({"ip":ip,"provider":provider,"verdict":"error","score":0,"detail":"Provider request failed","malicious":null})
        }
    };
    {
        let mut cache = a.ti_cache.lock().unwrap();
        if cache.len() >= 4096 {
            if let Some(old) = cache
                .iter()
                .min_by_key(|(_, (at, _))| *at)
                .map(|(key, _)| key.clone())
            {
                cache.remove(&old);
            }
        }
        cache.insert(cache_key, (Instant::now(), verdict.clone()));
    }
    if verdict["verdict"] == "malicious" {
        a.engine.lock().unwrap().alert(
            "THREAT_HIT",
            &ip.to_string(),
            "critical",
            format!("Threat intelligence flagged {ip}"),
            verdict.clone(),
        );
    }
    Ok(json!({"verdict":verdict,"config":cfg}))
}
pub fn threat_worker(a: App) {
    if crate::demo::enabled() {
        return;
    }
    let mut next = Instant::now();
    while !a.stop.load(std::sync::atomic::Ordering::Relaxed) {
        if Instant::now() >= next {
            let s = config(&a);
            let provider = s["ti_provider"].as_str().unwrap_or("none");
            let key = s["ti_api_key"].as_str().unwrap_or("");
            if provider != "none" && !key.is_empty() {
                let prefix = format!("{provider}:{}:", integrity::sha(key));
                let ips = a
                    .engine
                    .lock()
                    .unwrap()
                    .nodes
                    .values()
                    .filter(|n| !n.private)
                    .map(|n| n.ip.clone())
                    .collect::<Vec<_>>();
                let ip = {
                    let cache = a.ti_cache.lock().unwrap();
                    ips.into_iter().find(|ip| {
                        !cache
                            .get(&format!("{prefix}{ip}"))
                            .is_some_and(|(at, _)| at.elapsed() < Duration::from_secs(3600))
                    })
                };
                if let Some(ip) = ip {
                    let _ = threat(&a, &json!({"ip":ip}));
                    next = Instant::now() + Duration::from_secs(15);
                }
            }
        }
        crate::interruptible_sleep(&a.stop, Duration::from_millis(500));
    }
}
fn blocklist(a: &App, body: &Value) -> ApiResult {
    let path = body["path"].as_str().filter(|s| !s.is_empty());
    let url = body["url"].as_str().filter(|s| !s.is_empty());
    if path.is_some() == url.is_some() {
        return Err(bad("Provide exactly one of path or url"));
    }
    let kind = body["kind"].as_str().unwrap_or("domain");
    let action = body["action"].as_str().unwrap_or("block");
    if !["domain", "ip"].contains(&kind) || !["block", "sinkhole"].contains(&action) {
        return Err(bad("Invalid blocklist kind or action"));
    }
    let text = if let Some(url) = url {
        let url = reqwest::Url::parse(url).map_err(|_| bad("Invalid URL"))?;
        if !["http", "https"].contains(&url.scheme()) {
            return Err(bad("URL must use HTTP(S)"));
        }
        a.runtime.block_on(async {
            let http = reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::limited(3))
                .timeout(Duration::from_secs(10))
                .build()
                .map_err(|_| bad("HTTP client unavailable"))?;
            let mut reply = http
                .get(url)
                .header(
                    "User-Agent",
                    concat!("Genyra-Snitch/", env!("CARGO_PKG_VERSION")),
                )
                .send()
                .await
                .map_err(|_| bad("Blocklist fetch failed"))?
                .error_for_status()
                .map_err(|_| bad("Blocklist returned an HTTP error"))?;
            let mut bytes = Vec::new();
            while let Some(chunk) = reply
                .chunk()
                .await
                .map_err(|_| bad("Blocklist transfer failed"))?
            {
                if bytes.len() + chunk.len() > 4 * 1024 * 1024 {
                    return Err(bad("Blocklist exceeds 4 MiB"));
                }
                bytes.extend_from_slice(&chunk);
            }
            Ok(String::from_utf8_lossy(&bytes).into_owned())
        })?
    } else {
        let path = path.unwrap();
        let path = if let Some(rest) = path.strip_prefix("~/") {
            std::path::PathBuf::from(std::env::var_os("HOME").unwrap_or_default()).join(rest)
        } else {
            path.into()
        };
        let file = fs::File::open(path).map_err(|e| bad(e.to_string()))?;
        let mut bytes = Vec::new();
        file.take(4 * 1024 * 1024 + 1)
            .read_to_end(&mut bytes)
            .map_err(|e| bad(e.to_string()))?;
        if bytes.len() > 4 * 1024 * 1024 {
            return Err(bad("Blocklist exceeds 4 MiB"));
        }
        String::from_utf8_lossy(&bytes).into_owned()
    };
    let entries = crate::blocklist::parse(&text, kind);
    let limit = body["max_entries"].as_u64().unwrap_or(500).clamp(1, 5000) as usize;
    let mut rules = config(a)["firewall_rules"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    let mut added = 0;
    let mut skipped = 0;
    for value in entries.iter().take(limit) {
        if rules.len() >= 5000 || crate::blocklist::existing(&rules, kind, value, action) {
            skipped += 1;
            continue;
        }
        let rule = json!({"id":uuid::Uuid::new_v4().to_string(),"kind":kind,"value":value,"action":action,"rate":64,"enabled":true,"applied":false,"created_at":chrono::Utc::now().to_rfc3339()});
        if validate_firewall(&rule).is_err() {
            skipped += 1;
            continue;
        }
        rules.push(rule);
        added += 1;
    }
    save(a, "firewall_rules", json!(rules))?;
    let applied = sync_firewall(a);
    Ok(
        json!({"ok":true,"remote_fetch":url.is_some(),"kind":kind,"parsed":entries.len(),"added":added,"skipped":skipped,"truncated":entries.len()>limit,"applied":applied.is_ok(),"error":applied.err()}),
    )
}
fn indicators(a: &App) -> Vec<String> {
    let e = a.engine.lock().unwrap();
    let mut out: Vec<String> = e
        .alerts
        .iter()
        .filter_map(|a| {
            a["node_id"]
                .as_str()
                .filter(|s| !s.is_empty())
                .map(str::to_string)
        })
        .collect();
    out.extend(
        e.settings["firewall_rules"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|r| r["value"].as_str().map(str::to_string)),
    );
    out.sort();
    out.dedup();
    out.truncate(4096);
    out
}
fn positions(s: &str) -> [usize; 4] {
    let hash = Sha256::digest(s.trim().to_lowercase().as_bytes());
    let h1 = u64::from_be_bytes(hash[..8].try_into().unwrap()) as u128;
    let h2 = u64::from_be_bytes(hash[8..16].try_into().unwrap()) as u128;
    std::array::from_fn(|i| ((h1 + i as u128 * h2) % 8192) as usize)
}
fn hex_bytes(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) || !s.is_ascii() {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}
fn proof_root(mut leaves: Vec<Vec<u8>>) -> String {
    if leaves.is_empty() {
        return integrity::sha("empty");
    }
    leaves.sort();
    while leaves.len() > 1 {
        if leaves.len() % 2 == 1 {
            leaves.push(leaves.last().unwrap().clone());
        }
        leaves = leaves
            .chunks(2)
            .map(|p| Sha256::digest([p[0].as_slice(), p[1].as_slice()].concat()).to_vec())
            .collect();
    }
    leaves[0].iter().map(|b| format!("{b:02x}")).collect()
}
pub(crate) fn ioc_pack(a: &App, proof: bool) -> Value {
    let items = indicators(a);
    if proof {
        let entries: Vec<_> = items
            .iter()
            .map(|s| {
                let salt = uuid::Uuid::new_v4();
                let bytes = [
                    salt.as_bytes().as_slice(),
                    s.trim().to_lowercase().as_bytes(),
                ]
                .concat();
                json!({"salt":salt.simple().to_string(),"leaf":integrity::sha(bytes)})
            })
            .collect();
        let root = proof_root(
            entries
                .iter()
                .filter_map(|e| hex_bytes(e["leaf"].as_str().unwrap()))
                .collect(),
        );
        return json!({"format":"snitch-ioc-proof/1","created":chrono::Utc::now().timestamp(),"count":items.len(),"entries":entries,"root":root});
    }
    let mut bits = vec![0u8; 1024];
    for s in &items {
        for p in positions(s) {
            bits[p / 8] |= 1 << (p % 8);
        }
    }
    let mut randomness = [0u8; 8192];
    if fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut randomness))
        .is_ok()
    {
        for (i, r) in randomness.iter().enumerate() {
            if *r < 5 {
                bits[i / 8] ^= 1 << (i % 8);
            }
        }
    }
    json!({"format":"snitch-ioc-pack/1","created":chrono::Utc::now().timestamp(),"count":items.len(),"m":8192,"k":4,"flip":0.02,"bits_b64":STANDARD.encode(bits)})
}
fn check_ioc(a: &App, pack: &Value) -> Value {
    let candidates: Vec<_> = a
        .engine
        .lock()
        .unwrap()
        .nodes
        .keys()
        .take(2048)
        .cloned()
        .collect();
    let mut hints = Vec::new();
    if pack["format"] == "snitch-ioc-proof/1" {
        let Some(entries) = pack["entries"].as_array().filter(|e| e.len() <= 4096) else {
            return json!({"ok":false,"error":"Bad entries","hints":[]});
        };
        let pairs: Option<Vec<_>> = entries
            .iter()
            .map(|e| {
                Some((
                    hex_bytes(e["leaf"].as_str()?)?,
                    hex_bytes(e["salt"].as_str()?)?,
                ))
            })
            .collect();
        let Some(pairs) = pairs else {
            return json!({"ok":false,"error":"Corrupt entries","hints":[]});
        };
        if proof_root(pairs.iter().map(|(h, _)| h.clone()).collect()) != pack["root"] {
            return json!({"ok":false,"error":"Root mismatch","hints":[]});
        }
        for item in &candidates {
            for (hash, salt) in &pairs {
                if Sha256::digest([salt.as_slice(), item.trim().to_lowercase().as_bytes()].concat())
                    .as_slice()
                    == hash.as_slice()
                {
                    hints.push(json!({"indicator":item,"confidence":"cryptographic membership"}));
                    break;
                }
            }
        }
    } else {
        let Ok(bits) = STANDARD.decode(pack["bits_b64"].as_str().unwrap_or("")) else {
            return json!({"ok":false,"error":"Corrupt bitfield","hints":[]});
        };
        if pack["format"] != "snitch-ioc-pack/1"
            || pack["m"] != 8192
            || pack["k"] != 4
            || bits.len() != 1024
        {
            return json!({"ok":false,"error":"Pack parameters mismatch","hints":[]});
        }
        for item in &candidates {
            if positions(item)
                .iter()
                .all(|p| bits[p / 8] & (1 << (p % 8)) != 0)
            {
                hints.push(json!({"indicator":item,"confidence":"probabilistic — bloom+noise cannot prove presence"}));
            }
        }
    }
    json!({"ok":true,"hints":hints,"checked":candidates.len()})
}
fn enroll(a: &App, body: &Value) -> ApiResult {
    let name = body["name"].as_str().unwrap_or("").trim();
    if name.is_empty() || name.len() > 80 {
        return Err(bad("Agent name required (max 80 characters)"));
    }
    let mut store = config(a)["agent_tokens"]
        .as_object()
        .cloned()
        .unwrap_or_default();
    if store.len() >= 4096 {
        return Err(bad("Agent limit reached"));
    }
    if store.values().any(|v| v["name"] == name) {
        return Err(error(StatusCode::CONFLICT, "Agent already enrolled"));
    }
    let token = format!(
        "sagt_{}{}",
        uuid::Uuid::new_v4().simple(),
        uuid::Uuid::new_v4().simple()
    );
    store.insert(
        integrity::sha(&token),
        json!({"name":name,"created":chrono::Utc::now().timestamp_millis()as f64/1000.}),
    );
    save(a, "agent_tokens", json!(store))?;
    Ok(json!({"ok":true,"agent":name,"token":token}))
}
fn ingest(a: &App, body: &Value) -> ApiResult {
    let events = body["events"]
        .as_array()
        .ok_or_else(|| bad("events must be an array"))?;
    let host = body["_trusted_agent"]
        .as_str()
        .or_else(|| body["host"].as_str())
        .unwrap_or("agent")
        .chars()
        .take(253)
        .collect::<String>();
    let minute = chrono::Utc::now().format("%Y-%m-%dT%H:%M").to_string();
    let mut accepted = 0;
    let mut alerts = 0;
    let mut e = a.engine.lock().unwrap();
    for event in events.iter().take(1000) {
        let Some(ip) = event["dst_ip"]
            .as_str()
            .filter(|s| s.parse::<IpAddr>().is_ok())
        else {
            continue;
        };
        let bytes = event["bytes"].as_u64().unwrap_or(0).min(1 << 40);
        if e.pending.history.len() > 20000 {
            continue;
        }
        let c = e
            .pending
            .history
            .entry((minute.clone(), "host".into(), format!("{host}:{ip}")))
            .or_default();
        c.0 += 1;
        c.1 += bytes;
        let process = event["process"]
            .as_str()
            .filter(|s| s.len() <= 253)
            .unwrap_or("");
        if !process.is_empty() {
            let c = e
                .pending
                .history
                .entry((
                    minute.clone(),
                    "process".into(),
                    format!("{host}:{process}"),
                ))
                .or_default();
            c.0 += 1;
            c.1 += bytes;
        }
        let fields = json!({"remote_ip":ip,"host":event["sni"].as_str().unwrap_or(""),"process_name":process,"remote_port":event["dst_port"].as_u64().unwrap_or(0),"protocol":event["proto"].as_str().unwrap_or("tcp").to_lowercase(),"direction":if event["direction"]=="in"{"in"}else{"out"},"size":bytes});
        for rule in e.rules.matches(&fields) {
            e.alert("CUSTOM_RULE",ip,rule["severity"].as_str().unwrap_or("info"),format!("[{host}] Custom rule matched: {}",rule["name"].as_str().unwrap_or("unnamed")),json!({"rule":rule,"process":process,"agent":host,"direction":fields["direction"],"ip":ip}));
            alerts += 1;
        }
        accepted += 1;
    }
    Ok(
        json!({"ok":true,"agent":body["agent"],"host":host,"received":events.len(),"accepted":accepted,"alerts":alerts,"truncated":events.len()>1000}),
    )
}
fn audit(a: &App) -> Value {
    let mut alerts = crate::storage::alerts_limit(&a.db.lock().unwrap(), 500).unwrap_or_default();
    let (risky, unresolved, rules, lockdown, blocked, enabled) = {
        let e = a.engine.lock().unwrap();
        let mut ids = alerts
            .iter()
            .filter_map(|v| v["id"].as_str().map(str::to_string))
            .collect::<std::collections::HashSet<_>>();
        for alert in &e.alerts {
            if ids.insert(alert["id"].as_str().unwrap_or("").into()) {
                alerts.push(alert.clone());
            }
        }
        alerts.sort_by(|a, b| b["timestamp"].as_str().cmp(&a["timestamp"].as_str()));
        alerts.truncate(500);
        let mut risky = e
            .nodes
            .values()
            .filter(|n| {
                n.country_code.as_deref().is_some_and(|c| {
                    ["RU", "KP", "IR", "BY", "CU", "SY", "AF", "MM", "VE", "NI"].contains(&c)
                })
            })
            .map(|n| n.ip.clone())
            .collect::<Vec<_>>();
        risky.sort();
        let mut unresolved = e
            .nodes
            .values()
            .filter(|n| n.label == n.ip)
            .map(|n| n.ip.clone())
            .collect::<Vec<_>>();
        unresolved.sort();
        (
            risky,
            unresolved,
            e.settings["firewall_rules"]
                .as_array()
                .into_iter()
                .flatten()
                .filter(|r| r["enabled"] != false)
                .count(),
            e.settings["firewall_lockdown"] == true,
            e.blocked_counts.values().sum::<u64>(),
            e.settings["integrity_watch"] != false,
        )
    };
    let mut counts = HashMap::<String, u64>::new();
    let mut critical = 0u64;
    let mut warning = 0u64;
    for alert in alerts {
        *counts
            .entry(alert["type"].as_str().unwrap_or("?").into())
            .or_default() += 1;
        if alert["severity"] == "critical" {
            critical += 1;
        }
        if alert["severity"] == "warning" {
            warning += 1;
        }
    }
    let mut recs = Vec::new();
    for (kind, level, text) in [
        (
            "CLEARTEXT",
            "high",
            "Plaintext traffic observed; prefer encrypted services.",
        ),
        (
            "DNS_TUNNEL",
            "high",
            "Inspect the process associated with possible DNS tunnelling.",
        ),
        (
            "THREAT_HIT",
            "high",
            "Review the reported IPs and consider firewall rules.",
        ),
        (
            "BEACON",
            "medium",
            "Review the executable hashes behind periodic connections.",
        ),
    ] {
        if counts.get(kind).copied().unwrap_or(0) > 0 {
            recs.push(json!({"level":level,"text":text}));
        }
    }
    if lockdown {
        recs.push(json!({"level":"info","text":"Lockdown is enabled; outbound public traffic is blocked."}));
    }
    if !risky.is_empty() {
        recs.push(json!({"level":"medium","text":"Verify that contacts with high-risk countries match expected services."}));
    }
    if rules == 0 && !lockdown {
        recs.push(json!({"level":"low","text":"No firewall rules configured; create rules for unwanted connections."}));
    }
    if unresolved.len() > 20 {
        recs.push(json!({"level":"low","text":"Many hosts have no resolved name; check DNS and GeoIP availability."}));
    }
    let score = 100u64.saturating_sub(
        (critical * 8).min(60)
            + warning.min(20)
            + risky.len().min(10) as u64
            + if lockdown { 5 } else { 0 },
    );
    let mut integrity = a.integrity.lock().unwrap().status(enabled);
    if let Some(v) = integrity["findings"].as_array_mut() {
        let n = v.len().saturating_sub(10);
        v.drain(..n);
    }
    json!({"score":score,"period":"last 500 alerts","alert_counts":counts,"critical":critical,"warning":warning,"findings":{"high_risk_countries":risky,"unresolved_hosts":unresolved.into_iter().take(50).collect::<Vec<_>>(),"cleartext_alerts":counts.get("CLEARTEXT").copied().unwrap_or(0),"dns_tunnel_alerts":counts.get("DNS_TUNNEL").copied().unwrap_or(0),"threat_hits":counts.get("THREAT_HIT").copied().unwrap_or(0)},"firewall":{"active_rules":rules,"lockdown":lockdown,"blocked_attempts":blocked,"supported":command_exists("nft"),"platform":"linux"},"threat_intel":ti_config(a),"integrity":integrity,"recommendations":recs})
}
#[cfg(windows)]
fn sandbox(_: &Value) -> ApiResult {
    Err(error(
        StatusCode::NOT_IMPLEMENTED,
        "Windows has no equivalent network-denial sandbox in upstream Snitch; this tool requires Linux or macOS",
    ))
}
#[cfg(unix)]
fn sandbox(body: &Value) -> ApiResult {
    let path = body["path"]
        .as_str()
        .ok_or_else(|| bad("Absolute executable path required"))?;
    if !std::path::Path::new(path).is_absolute() {
        return Err(bad("Path must be absolute"));
    }
    let args: Vec<_> = body["args"]
        .as_array()
        .into_iter()
        .flatten()
        .take(8)
        .filter_map(Value::as_str)
        .map(|s| s.chars().take(256).collect::<String>())
        .collect();
    let seconds = body["seconds"].as_u64().unwrap_or(10).clamp(1, 60);
    #[cfg(target_os = "linux")]
    let mut command = {
        let mut command = Command::new("unshare");
        command.args(["-Urn", "--", path]);
        command
    };
    #[cfg(target_os = "macos")]
    let mut command = {
        let mut command = Command::new("/usr/bin/sandbox-exec");
        command.args(["-p","(version 1)(allow default)(deny network*)(deny network-bind)(deny network-outbound)(deny network-inbound)",path]);
        command
    };
    let mut child = command
        .args(args)
        .process_group(0)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| bad(e.to_string()))?;
    let out = child.stdout.take().unwrap();
    let err = child.stderr.take().unwrap();
    let reader = std::thread::spawn(move || {
        let mut b = Vec::new();
        let _ = out.take(65536).read_to_end(&mut b);
        b
    });
    let errors = std::thread::spawn(move || {
        let mut b = Vec::new();
        let _ = err.take(65536).read_to_end(&mut b);
        b
    });
    let start = Instant::now();
    let mut timed_out = false;
    let exit_status = loop {
        if let Some(status) = child.try_wait().map_err(|e| bad(e.to_string()))? {
            break status;
        }
        if start.elapsed() > Duration::from_secs(seconds) {
            timed_out = true;
            unsafe {
                libc::kill(-(child.id() as i32), libc::SIGKILL);
            }
            break child.wait().map_err(|e| bad(e.to_string()))?;
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    // Descendants must not keep the output pipes open after the leader exits.
    unsafe {
        libc::kill(-(child.id() as i32), libc::SIGKILL);
    }
    let stdout = reader.join().unwrap_or_default();
    let stderr = errors.join().unwrap_or_default();
    Ok(
        json!({"ok":exit_status.success()&&!timed_out,"exit_code":exit_status.code(),"supported":true,"timed_out":timed_out,"stdout":String::from_utf8_lossy(&stdout),"stderr":String::from_utf8_lossy(&stderr),"network_denied":exit_status.success().then_some(true),"best_effort":cfg!(target_os="macos")}),
    )
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn bounded_rules_and_cidr() {
        let r = json!({"field":"remote_ip","op":"cidr","value":"10.0.0.0/8","severity":"warning","enabled":true});
        let rules = Rules::new(&json!([r]));
        assert_eq!(rules.matches(&json!({"remote_ip":"10.1.2.3"})).len(), 1);
        assert!(rules.matches(&json!({"remote_ip":"192.0.2.1"})).is_empty());
    }
    #[test]
    fn invalid_regex_rejected() {
        assert!(
            validate_rule(&json!({"field":"host","op":"regex","value":"[","severity":"info"}))
                .is_err()
        );
    }
}
