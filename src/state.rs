use crate::geodb;
use crate::{
    packet,
    process::{Key, Table},
};
use chrono::Utc;
use serde::Serialize;
use serde_json::{json, Value};
use std::{
    collections::{HashMap, HashSet, VecDeque},
    net::IpAddr,
    path::Path,
    time::{Duration, Instant},
};

pub const MAX_NODES: usize = 4096;
const MAX_NAMES: usize = 8192;
#[derive(Clone, Serialize, Default)]
pub struct Counts {
    pub bytes: u64,
    pub packets: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pid: Option<u32>,
}
#[derive(Clone, Serialize)]
pub struct Node {
    pub id: String,
    pub ip: String,
    pub label: String,
    pub category: String,
    pub color: String,
    pub country: Option<String>,
    pub country_code: Option<String>,
    pub city: Option<String>,
    pub lat: Option<f64>,
    pub lon: Option<f64>,
    pub org: Option<String>,
    pub asn: Option<u64>,
    pub bytes: u64,
    pub packets: u64,
    pub alerted: bool,
    pub processes: HashMap<String, Counts>,
    #[serde(flatten)]
    pub extra: serde_json::Map<String, Value>,
    #[serde(skip)]
    pub last: Instant,
    #[serde(skip)]
    pub private: bool,
}
#[derive(Clone, Serialize)]
pub struct Edge {
    pub id: String,
    pub source: String,
    pub target: String,
    pub protocol: String,
    pub label: String,
    pub color: String,
    pub bytes: u64,
    pub packets: u64,
}
#[derive(Default, Serialize)]
pub struct Stats {
    pub notification_failures: u64,
    pub notification_dropped: u64,
    pub captured: u64,
    pub processed: u64,
    pub unparsed: u64,
    pub noise_filtered: u64,
    pub nonlocal: u64,
    pub filtered: u64,
    pub unattributed: u64,
    pub pcap_dropped: u32,
    pub pcap_if_dropped: u32,
    pub graph_evictions: u64,
    pub alert_overflow: u64,
    pub history_overflow: u64,
    pub attribution_incomplete: bool,
}
#[derive(Default)]
pub struct Pending {
    pub traffic: HashMap<(String, String), (u64, u64)>,
    pub history: HashMap<(String, String, String), (u64, u64)>,
    pub alerts: Vec<Value>,
    pub devices: HashMap<String, Value>,
}

pub struct Classifier {
    trackers: HashSet<String>,
    cdns: HashSet<String>,
}
impl Classifier {
    pub fn new(data: &Path) -> Self {
        fn list(data: &Path, name: &str, bundled: &str) -> HashSet<String> {
            std::fs::read_to_string(data.join("lists").join(name))
                .unwrap_or_else(|_| bundled.into())
                .lines()
                .map(str::trim)
                .filter(|s| !s.is_empty() && !s.starts_with('#'))
                .map(str::to_lowercase)
                .collect()
        }
        Self {
            trackers: list(
                data,
                "trackers.txt",
                include_str!("../resources/trackers.txt"),
            ),
            cdns: list(data, "cdns.txt", include_str!("../resources/cdns.txt")),
        }
    }
    fn matches(set: &HashSet<String>, name: &str) -> bool {
        let name = name.trim_end_matches('.');
        let mut suffix = name;
        loop {
            if set.contains(suffix) {
                return true;
            }
            let Some((_, next)) = suffix.split_once('.') else {
                return false;
            };
            suffix = next;
        }
    }
    pub fn classify(
        &self,
        name: &str,
        port: u16,
        proto: &str,
    ) -> (&'static str, &'static str, String) {
        let label = match (port, proto) {
            (443, "UDP") => "QUIC/HTTP3",
            (443, _) => "HTTPS",
            (80, _) => "HTTP",
            (53, _) => "DNS",
            (22, _) => "SSH",
            (21, _) => "FTP",
            (25, _) => "SMTP",
            (3306, _) => "MySQL",
            (5432, _) => "PostgreSQL",
            (6379, _) => "Redis",
            _ => proto,
        }
        .to_string();
        let (category, color) = if Self::matches(&self.trackers, name) {
            ("tracking", "#f59e0b")
        } else if Self::matches(&self.cdns, name) {
            ("cdn", "#6366f1")
        } else {
            match port {
                443 => ("safe", "#22c55e"),
                80 => ("safe", "#84cc16"),
                53 => ("dns", "#38bdf8"),
                22 => ("admin", "#fb923c"),
                _ => ("unknown", "#94a3b8"),
            }
        };
        (category, color, label)
    }
}

pub fn private(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v) => v.is_private() || v.is_link_local() || v.is_loopback(),
        IpAddr::V6(v) => v.is_unique_local() || v.is_unicast_link_local() || v.is_loopback(),
    }
}
fn noise(ip: IpAddr) -> bool {
    ip.is_multicast()
        || ip.is_unspecified()
        || ip.is_loopback()
        || matches!(ip,IpAddr::V4(v) if v.is_broadcast())
}

pub struct Engine {
    pub nodes: HashMap<String, Node>,
    pub edges: HashMap<String, Edge>,
    pub alerts: VecDeque<Value>,
    names: HashMap<IpAddr, (String, Instant)>,
    ptr_named: HashSet<IpAddr>,
    ptr_inflight: HashSet<IpAddr>,
    ptr_failed: HashMap<IpAddr, Instant>,
    pub ptr_queue: VecDeque<(IpAddr, u16, &'static str)>,
    ptr_enabled: bool,
    city: Option<geodb::Reader>,
    asn: Option<geodb::Reader>,
    classifier: Classifier,
    pub settings: Value,
    pub iface: String,
    pub linktype: i32,
    pub capturing: bool,
    pub error: Option<String>,
    pub storage_error: Option<String>,
    pub stats: Stats,
    pub pending: Pending,
    pub local_ips: HashSet<IpAddr>,
    pub started: Instant,
    pub detector: crate::anomaly::Detector,
    pub media: Value,
    pub kernel: std::sync::Arc<crate::kernel::Kernel>,
    cooldown: HashMap<String, Instant>,
    scan: HashMap<String, (Instant, HashSet<u16>)>,
    upload: HashMap<String, VecDeque<(u64, u64)>>,
    ports: HashSet<u16>,
    excluded: HashSet<String>,
    whitelist: HashSet<String>,
    watch: Vec<String>,
    minute: String,
    dirty: HashSet<String>,
    pub recent_packets: VecDeque<Value>,
    events_packets: Vec<Value>,
    events_alerts: Vec<Value>,
    pub raw_frames: VecDeque<(f64, Vec<u8>, u32, String, String)>,
    raw_bytes: usize,
    pub(crate) rules: crate::security::Rules,
    pub firewall_actions: VecDeque<Value>,
    pub blocked_counts: HashMap<String, u64>,
    firewall: crate::firewall::Policy,
    tls: crate::tlscert::Inspector,
    pub notifications: VecDeque<Value>,
    rule_blocks: HashSet<(String, String)>,
    removed: Vec<String>,
}
impl Engine {
    pub fn new(
        data: &Path,
        iface: String,
        settings: Value,
        alerts: Vec<Value>,
        local_ips: HashSet<IpAddr>,
    ) -> Self {
        fn strings(v: &Value, key: &str) -> HashSet<String> {
            v[key]
                .as_array()
                .map(|a| {
                    a.iter()
                        .filter_map(Value::as_str)
                        .map(str::to_string)
                        .collect()
                })
                .unwrap_or_default()
        }
        let ports = settings["ports"]
            .as_array()
            .map(|a| {
                a.iter()
                    .filter_map(Value::as_u64)
                    .filter_map(|p| u16::try_from(p).ok())
                    .collect()
            })
            .unwrap_or_default();
        let excluded = strings(&settings, "excluded_processes");
        let whitelist = strings(&settings, "whitelisted_ips");
        let watch = strings(&settings, "watchlist").into_iter().collect();
        let rules = crate::security::Rules::new(&settings["custom_rules"]);
        let firewall = crate::firewall::Policy::new(&settings);
        let detector = crate::anomaly::Detector::new(&settings["app_baselines"]);
        Self {
            nodes: HashMap::new(),
            edges: HashMap::new(),
            alerts: alerts.into(),
            names: HashMap::new(),
            ptr_named: HashSet::new(),
            ptr_inflight: HashSet::new(),
            ptr_failed: HashMap::new(),
            ptr_queue: VecDeque::new(),
            ptr_enabled: !crate::demo::enabled()
                && std::env::var("SNITCH_DISABLE_PTR").as_deref() != Ok("1")
                && std::env::var_os("SNITCH_REPLAY_PCAP").is_none(),
            city: geodb::open(data.join("geo/dbip-city-lite.mmdb")).ok(),
            asn: geodb::open(data.join("geo/dbip-asn-lite.mmdb")).ok(),
            classifier: Classifier::new(data),
            settings,
            firewall,
            tls: crate::tlscert::Inspector::default(),
            blocked_counts: HashMap::new(),
            iface,
            linktype: 1,
            capturing: true,
            error: None,
            storage_error: None,
            stats: Stats::default(),
            pending: Pending::default(),
            local_ips,
            started: Instant::now(),
            cooldown: HashMap::new(),
            scan: HashMap::new(),
            upload: HashMap::new(),
            ports,
            excluded,
            whitelist,
            watch,
            minute: Utc::now().format("%Y-%m-%dT%H:%M").to_string(),
            dirty: HashSet::new(),
            recent_packets: VecDeque::new(),
            events_packets: Vec::new(),
            events_alerts: Vec::new(),
            raw_frames: VecDeque::new(),
            raw_bytes: 0,
            rules,
            firewall_actions: VecDeque::new(),
            notifications: VecDeque::new(),
            rule_blocks: HashSet::new(),
            detector,
            media: json!({"mic":[],"camera":[],"supported":true}),
            kernel: std::sync::Arc::new(crate::kernel::Kernel::default()),
            removed: Vec::new(),
        }
    }
    pub fn tick(&mut self) {
        self.minute = Utc::now().format("%Y-%m-%dT%H:%M").to_string();
        self.names.retain(|_, (_, expiry)| *expiry > Instant::now());
        self.ptr_named.retain(|ip| self.names.contains_key(ip));
        self.cooldown
            .retain(|_, at| at.elapsed() < Duration::from_secs(3600));
        self.scan
            .retain(|_, (at, _)| at.elapsed() < Duration::from_secs(60));
        let cutoff = Utc::now().timestamp().max(60) as u64 - 60;
        self.upload.retain(|_, q| {
            while q.front().is_some_and(|(s, _)| *s < cutoff) {
                q.pop_front();
            }
            !q.is_empty()
        });
        for (ip, node) in &mut self.nodes {
            if node.private
                && node.last.elapsed() > Duration::from_secs(120)
                && node.extra["online"] == true
            {
                node.extra.insert("online".into(), json!(false));
                self.dirty.insert(ip.clone());
            }
        }
        let stale: HashSet<_> = self
            .nodes
            .iter()
            .filter(|(_, n)| !n.private && n.last.elapsed() > Duration::from_secs(3600))
            .map(|(k, _)| k.clone())
            .collect();
        self.nodes.retain(|k, _| !stale.contains(k));
        self.edges.retain(|_, e| !stale.contains(&e.target));
        self.removed.extend(stale);
    }
    fn node(&self, ip: IpAddr) -> Node {
        fn record(reader: &Option<geodb::Reader>, ip: IpAddr) -> Value {
            reader
                .as_ref()
                .and_then(|r| r.lookup(ip).ok())
                .and_then(|l| l.decode::<Value>().ok().flatten())
                .unwrap_or(Value::Null)
        }
        let geo = record(&self.city, ip);
        let asn = record(&self.asn, ip);
        fn s(v: &Value, p: &str) -> Option<String> {
            v.pointer(p).and_then(Value::as_str).map(str::to_string)
        }
        let id = ip.to_string();
        Node {
            id: id.clone(),
            ip: id.clone(),
            label: id,
            category: "unknown".into(),
            color: "#94a3b8".into(),
            country: s(&geo, "/country/names/en"),
            country_code: s(&geo, "/country/iso_code"),
            city: s(&geo, "/city/names/en"),
            lat: geo.pointer("/location/latitude").and_then(Value::as_f64),
            lon: geo.pointer("/location/longitude").and_then(Value::as_f64),
            org: s(&asn, "/autonomous_system_organization"),
            asn: asn["autonomous_system_number"].as_u64(),
            bytes: 0,
            packets: 0,
            alerted: false,
            processes: HashMap::new(),
            extra: serde_json::Map::new(),
            last: Instant::now(),
            private: private(ip),
        }
    }
    pub fn graph(&self) -> Value {
        let mut nodes: Vec<_> = self.nodes.values().map(|n| json!(n)).collect();
        nodes.push(json!({"id":"local","label":"This computer","type":"local","category":"local","bytes":0,"packets":0}));
        json!({"nodes":nodes,"edges":self.edges.values().collect::<Vec<_>>()})
    }
    pub fn status(&self) -> Value {
        json!({"capturing":self.capturing&&self.error.is_none(),"capture_error":self.error,"ports":self.ports,"excluded_processes":self.excluded,"whitelisted_ips":self.whitelist,"watchlist":self.watch,"interface":self.iface,"ssid":"","backend":"rust","demo":crate::demo::enabled()})
    }
    pub fn diagnostics(&self) -> Value {
        json!({"backend":"rust","product":"Genyra Snitch","version":env!("CARGO_PKG_VERSION"),"platform":std::env::consts::OS,"native_backend":true,"validation_manifest":"compatibility.json","invalid_custom_rules":self.rules.invalid,"uptime_s":self.started.elapsed().as_secs(),"capture":self.status(),"storage_error":self.storage_error,"stats":self.stats,"nodes":self.nodes.len(),"max_nodes":MAX_NODES,"geo_city_loaded":self.city.is_some(),"geo_asn_loaded":self.asn.is_some(),"detection_rules":["NEW_HOST","NEW_LAN_DEVICE","SUSPICIOUS_PORT","PORT_SCAN","UPLOAD_SPIKE","WATCHLIST_HIT","CUSTOM_RULE","BEACON","VOLUME_SPIKE","ICMP_TUNNEL","DGA_SUSPECT","SUSPICIOUS_PROCESS","MEDIA_EXFIL","CLEARTEXT","DNS_TUNNEL","HIGH_ENTROPY","PROTO_MISMATCH","MINING_SUSPECT","BASELINE_DEVIATION","ML_ANOMALY","TLS_CERT","BLOCKED_ATTEMPT"],"pending_migration":[]})
    }
    pub fn alert(&mut self, kind: &str, ip: &str, severity: &str, message: String, details: Value) {
        if self.settings["suppressions"]
            .as_array()
            .is_some_and(|rules| {
                rules.iter().any(|r| {
                    (r["type"].as_str().unwrap_or("").is_empty() || r["type"] == kind)
                        && (r["ip"].as_str().unwrap_or("").is_empty()
                            || r["ip"] == ip
                            || r["ip"] == "*")
                })
            })
        {
            return;
        }
        let key = format!(
            "{kind}:{ip}:{}",
            details.get("pid").map(Value::to_string).unwrap_or_default()
        );
        if self
            .cooldown
            .get(&key)
            .is_some_and(|t| t.elapsed() < Duration::from_secs(60))
        {
            return;
        }
        if self.cooldown.len() >= 16384 {
            return;
        }
        self.cooldown.insert(key, Instant::now());
        let a = json!({"id":format!("rust-{}-{}",Utc::now().timestamp_nanos_opt().unwrap_or_default(),self.stats.processed),"timestamp":Utc::now().to_rfc3339(),"type":kind,"severity":severity,"message":message,"node_id":ip,"details":details});
        if ["warning", "critical"].contains(&severity)
            && (self.settings["webhook_enabled"] == true
                || self.settings["syslog_addr"]
                    .as_str()
                    .is_some_and(|s| !s.is_empty()))
        {
            if self.notifications.len() < 500 {
                self.notifications.push_back(a.clone());
            } else {
                self.stats.notification_dropped += 1;
            }
        }
        if self.events_alerts.len() < 1000 {
            self.events_alerts.push(a.clone());
        }
        if let Some(n) = self.nodes.get_mut(ip) {
            n.alerted = true;
        }
        if self.alerts.len() >= 100 {
            self.alerts.pop_back();
        }
        self.alerts.push_front(a.clone());
        if self.pending.alerts.len() < 1000 {
            self.pending.alerts.push(a);
        } else {
            self.stats.alert_overflow += 1;
        }
    }
    pub fn packet(&mut self, b: &[u8], wirelen: u32, link: i32, table: &Table) {
        self.stats.captured += 1;
        if !self.capturing {
            return;
        }
        if crate::observer::learn_frame(self, b, link) {
            return;
        }
        let Some(p) = packet::parse(b, link) else {
            self.stats.unparsed += 1;
            return;
        };
        let out = self.local_ips.contains(&p.src);
        let incoming = self.local_ips.contains(&p.dst);
        if !out && !incoming {
            self.stats.nonlocal += 1;
            return;
        }
        if !self.ports.is_empty()
            && !self.ports.contains(&p.sport)
            && !self.ports.contains(&p.dport)
        {
            self.stats.filtered += 1;
            return;
        }
        if p.proto == "UDP" && [53, 5353, 5355].contains(&p.sport) {
            for (ip, name, ttl) in packet::dns(p.payload) {
                if self.names.len() >= MAX_NAMES && !self.names.contains_key(&ip) {
                    continue;
                }
                self.names
                    .insert(ip, (name, Instant::now() + Duration::from_secs(ttl as u64)));
                self.ptr_named.remove(&ip);
            }
        }
        let (remote, port, local, lport) = if out {
            (p.dst, p.dport, p.src, p.sport)
        } else {
            (p.src, p.sport, p.dst, p.dport)
        };
        if noise(remote) || self.local_ips.contains(&remote) {
            self.stats.noise_filtered += 1;
            return;
        }
        let ip = remote.to_string();
        if self.ptr_enabled
            && !private(remote)
            && !self.names.contains_key(&remote)
            && !self.ptr_inflight.contains(&remote)
            && self.ptr_queue.len() < 1024
            && self.ptr_inflight.len() < 4096
            && !self
                .ptr_failed
                .get(&remote)
                .is_some_and(|at| at.elapsed() < Duration::from_secs(60))
        {
            self.ptr_inflight.insert(remote);
            self.ptr_queue.push_back((remote, port, p.proto));
        }
        let owner = table
            .lookup(&Key {
                proto: p.proto,
                local,
                port: lport,
                remote,
                rport: port,
            })
            .or_else(|| self.kernel.owner(remote, port));
        if self.whitelist.contains(&ip)
            || owner
                .as_ref()
                .is_some_and(|o| self.excluded.contains(&o.name))
        {
            self.stats.filtered += 1;
            return;
        }
        if owner.is_none() && ["TCP", "UDP"].contains(&p.proto) {
            self.stats.unattributed += 1;
        }
        if out && p.proto == "TCP" {
            if let Some(name) = packet::sni(p.payload) {
                if self.names.len() < MAX_NAMES || self.names.contains_key(&remote) {
                    self.names
                        .insert(remote, (name, Instant::now() + Duration::from_secs(3600)));
                    self.ptr_named.remove(&remote);
                }
            }
        }
        let name = self
            .names
            .get(&remote)
            .filter(|(_, at)| *at > Instant::now())
            .map(|(n, _)| n.clone())
            .unwrap_or_default();
        if let Some(rule) = self.firewall.matching(
            remote,
            port,
            &name,
            owner.as_ref().map(|o| o.name.as_str()).unwrap_or(""),
            out,
        ) {
            let id = rule["id"].as_str().unwrap_or("unknown").to_string();
            let count = if self.blocked_counts.len() < 5001 || self.blocked_counts.contains_key(&id)
            {
                let c = self.blocked_counts.entry(id).or_default();
                *c += 1;
                *c
            } else {
                0
            };
            self.alert("BLOCKED_ATTEMPT",&ip,"warning",format!("Traffic matched firewall rule: {}",rule["value"].as_str().unwrap_or("")),json!({"rule":rule,"count":count,"ip":ip,"port":port,"process":owner.as_ref().map(|o|&o.name)}));
        }
        if !out {
            if let Some(cert) = self.tls.feed(&p) {
                let mut reasons = Vec::new();
                if cert["self_signed"] == true {
                    reasons.push("self-signed leaf".to_string());
                }
                if crate::tlscert::mismatch(&name, &cert["sans"]) {
                    reasons.push(format!("SANs do not cover {name}"));
                }
                if !reasons.is_empty() {
                    self.alert("TLS_CERT",&ip,"warning",format!("TLS certificate anomaly for {}: {}",if name.is_empty(){&ip}else{&name},reasons.join(", ")),json!({"ip":ip,"host":name,"issuer":cert["issuer_cn"],"subject":cert["subject_cn"],"reasons":reasons,"pid":owner.as_ref().map(|o|o.pid),"process":owner.as_ref().map(|o|&o.name),"certificate":cert}));
                }
            }
        }
        let (category, color, label) = self.classifier.classify(&name, port, p.proto);
        let new = !self.nodes.contains_key(&ip);
        if new {
            if self.nodes.len() >= MAX_NODES {
                if let Some(old) = self
                    .nodes
                    .iter()
                    .min_by_key(|(_, n)| n.last)
                    .map(|(k, _)| k.clone())
                {
                    self.nodes.remove(&old);
                    self.removed.push(old.clone());
                    self.edges.retain(|_, e| e.target != old);
                    self.stats.graph_evictions += 1;
                }
            }
            self.nodes.insert(ip.clone(), self.node(remote));
        }
        let n = self.nodes.get_mut(&ip).unwrap();
        if !name.is_empty() {
            n.label = name.clone();
        }
        n.category = if n.private { "lan_device" } else { category }.into();
        n.color = color.into();
        n.bytes += wirelen as u64;
        n.packets += 1;
        n.last = Instant::now();
        if let Some(o) = &owner {
            if n.processes.len() < 128 || n.processes.contains_key(&o.name) {
                let c = n.processes.entry(o.name.clone()).or_default();
                c.bytes += wirelen as u64;
                c.packets += 1;
                c.pid = Some(o.pid);
            }
        }
        let id = format!("local-{ip}-{}", p.proto);
        let e = self.edges.entry(id.clone()).or_insert_with(|| Edge {
            id,
            source: "local".into(),
            target: ip.clone(),
            protocol: p.proto.into(),
            label: label.clone(),
            color: color.into(),
            bytes: 0,
            packets: 0,
        });
        e.bytes += wirelen as u64;
        e.packets += 1;
        e.label = label;
        e.color = color.into();
        self.stats.processed += 1;
        if !private(remote) {
            let country = self
                .nodes
                .get(&ip)
                .and_then(|n| n.country_code.clone())
                .unwrap_or_default();
            let process = owner.as_ref().map(|o| o.name.as_str()).unwrap_or("");
            let mic = self.media["mic"].as_array().is_some_and(|a| {
                a.iter()
                    .any(|s| s.as_str().is_some_and(|s| s.eq_ignore_ascii_case(process)))
            });
            let camera = self.media["camera"].as_array().is_some_and(|a| {
                a.iter()
                    .any(|s| s.as_str().is_some_and(|s| s.eq_ignore_ascii_case(process)))
            });
            let findings = self.detector.observe(crate::anomaly::Context {
                ip: &ip,
                host: if name.is_empty() { &ip } else { &name },
                observed_host: !self.ptr_named.contains(&remote),
                process,
                country: &country,
                port,
                proto: p.proto,
                out,
                size: wirelen,
                now: Utc::now().timestamp_micros() as f64 / 1e6,
                payload: p.payload,
                mic,
                camera,
            });
            for mut f in findings {
                f.details["pid"] = json!(owner.as_ref().map(|o| o.pid));
                self.alert(f.kind, &ip, f.severity, f.message, f.details);
            }
        }
        let fields = json!({"remote_ip":ip,"host":name,"remote_port":port,"protocol":p.proto.to_lowercase(),"direction":if out{"out"}else{"in"},"size":wirelen,"process_name":owner.as_ref().map(|o|o.name.as_str()).unwrap_or(""),"cmdline":owner.as_ref().map(|o|o.cmdline.as_str()).unwrap_or(""),"parent_name":owner.as_ref().and_then(|o|o.parent_name.as_deref()).unwrap_or(""),"country":self.nodes.get(&ip).and_then(|n|n.country_code.as_deref()).unwrap_or(""),"asn":self.nodes.get(&ip).and_then(|n|n.asn)});
        for rule in self.rules.matches(&fields) {
            if rule["action"] == "block" {
                self.queue_block(rule["id"].as_str().unwrap_or("custom"), &ip);
            }
            self.alert("CUSTOM_RULE",&ip,rule["severity"].as_str().unwrap_or("info"),format!("Custom rule matched: {}",rule["name"].as_str().unwrap_or("unnamed")),json!({"rule":rule,"ip":ip,"process":owner.as_ref().map(|o|&o.name),"pid":owner.as_ref().map(|o|o.pid)}));
        }
        self.dirty.insert(ip.clone());
        let stamp = Utc::now();
        let event = json!({"src_ip":p.src,"dst_ip":p.dst,"src_port":p.sport,"dst_port":p.dport,"remote_port":port,"protocol":p.proto,"size":wirelen,"timestamp":stamp.to_rfc3339(),"direction":if out{"out"}else{"in"},"process_name":owner.as_ref().map(|o|&o.name),"pid":owner.as_ref().map(|o|o.pid),"category":category,"color":color,"label":name});
        if self.recent_packets.len() >= 100 {
            self.recent_packets.pop_front();
        }
        self.recent_packets.push_back(event.clone());
        if self.events_packets.len() < 1000 {
            self.events_packets.push(event);
        }
        while self.raw_bytes + b.len() > 4 * 1024 * 1024 {
            if let Some((_, old, _, _, _)) = self.raw_frames.pop_front() {
                self.raw_bytes -= old.len();
            } else {
                break;
            }
        }
        self.raw_bytes += b.len();
        self.raw_frames.push_back((
            stamp.timestamp_micros() as f64 / 1e6,
            b.to_vec(),
            wirelen,
            ip.clone(),
            owner.as_ref().map(|o| o.name.clone()).unwrap_or_default(),
        ));
        // Minute keys are refreshed once per batch, never formatted per packet.
        let totals = self
            .pending
            .traffic
            .entry((self.minute.clone(), category.into()))
            .or_default();
        totals.0 += 1;
        totals.1 += wirelen as u64;
        for (dim, key) in [
            ("host", Some(ip.clone())),
            ("process", owner.as_ref().map(|o| o.name.clone())),
        ] {
            if let Some(key) = key {
                if self.pending.history.len() < 20000 {
                    let c = self
                        .pending
                        .history
                        .entry((self.minute.clone(), dim.into(), key))
                        .or_default();
                    c.0 += 1;
                    c.1 += wirelen as u64;
                } else {
                    self.stats.history_overflow += 1;
                }
            }
        }
        if new && !private(remote) {
            self.alert(
                "NEW_HOST",
                &ip,
                "info",
                format!("New remote host: {ip}"),
                json!({"ip":ip,"hostname":name}),
            );
        }
        if [4444, 4445, 1337, 31337, 6666, 6667, 1080, 9001, 9050].contains(&port) {
            self.alert(
                "SUSPICIOUS_PORT",
                &ip,
                "warning",
                format!("Traffic on suspicious port {port}"),
                json!({"port":port,"process":owner.as_ref().map(|o|&o.name)}),
            );
        }
        if self.watch.iter().any(|w| {
            w == &ip || (!name.is_empty() && (w == &name || name.ends_with(&format!(".{w}"))))
        }) {
            self.alert(
                "WATCHLIST_HIT",
                &ip,
                "warning",
                format!("Watchlist contact: {ip}"),
                json!({"ip":ip,"hostname":name}),
            );
        }
        if ![53, 80, 123, 443, 853].contains(&port) && self.scan.len() < MAX_NODES {
            let scan = self
                .scan
                .entry(ip.clone())
                .or_insert_with(|| (Instant::now(), HashSet::new()));
            if scan.0.elapsed() > Duration::from_secs(60) {
                *scan = (Instant::now(), HashSet::new());
            }
            if scan.1.len() < 21 {
                scan.1.insert(port);
            }
            if scan.1.len() > 20 {
                self.alert(
                    "PORT_SCAN",
                    &ip,
                    "warning",
                    format!("More than 20 remote ports in 60s: {ip}"),
                    json!({"ip":ip,"distinct_ports":21}),
                );
            }
        }
        if out {
            if let Some(o) = owner {
                let threshold = self.settings["upload_threshold_mb"]
                    .as_f64()
                    .unwrap_or(50.0)
                    .max(0.0)
                    * 1048576.0;
                if threshold > 0.0 && self.upload.len() < 4096 {
                    let sec = Utc::now().timestamp().max(60) as u64;
                    let q = self.upload.entry(o.name.clone()).or_default();
                    while q.front().is_some_and(|(s, _)| *s + 60 <= sec) {
                        q.pop_front();
                    }
                    if q.back().is_some_and(|(s, _)| *s == sec) {
                        q.back_mut().unwrap().1 += wirelen as u64;
                    } else {
                        q.push_back((sec, wirelen as u64));
                    }
                    let total: u64 = q.iter().map(|(_, b)| b).sum();
                    // Per-process cooldown, even if an uploader contacts many hosts.
                    let cooldown = format!("UPLOAD_SPIKE:{}", o.name);
                    if total as f64 >= threshold
                        && !self
                            .cooldown
                            .get(&cooldown)
                            .is_some_and(|t| t.elapsed() < Duration::from_secs(60))
                        && self.cooldown.len() < 16384
                    {
                        self.cooldown.insert(cooldown, Instant::now());
                        if self.settings["kill_switch_enabled"] == true {
                            self.queue_block("kill-switch", &ip);
                        }
                        self.alert("UPLOAD_SPIKE",&ip,"warning",format!("Upload spike: {} sent {:.1} MB in 60s",o.name,total as f64/1048576.0),json!({"process":o.name,"pid":o.pid,"mb":total as f64/1048576.0,"window_s":60}));
                    }
                }
            }
        }
    }
    pub fn apply_setting(&mut self, key: &str, value: Value) {
        self.settings[key] = value.clone();
        let strings = || {
            value
                .as_array()
                .map(|a| {
                    a.iter()
                        .filter_map(Value::as_str)
                        .map(str::to_string)
                        .collect::<HashSet<String>>()
                })
                .unwrap_or_default()
        };
        match key {
            "firewall_rules" | "firewall_lockdown" => {
                self.firewall = crate::firewall::Policy::new(&self.settings)
            }
            "custom_rules" => self.rules = crate::security::Rules::new(&value),
            "ports" => {
                self.ports = value
                    .as_array()
                    .map(|a| {
                        a.iter()
                            .filter_map(Value::as_u64)
                            .filter_map(|n| u16::try_from(n).ok())
                            .collect()
                    })
                    .unwrap_or_default();
                self.nodes.clear();
                self.edges.clear();
                self.cooldown.clear();
                self.scan.clear();
                self.upload.clear();
            }
            "excluded_processes" => self.excluded = strings(),
            "whitelisted_ips" => {
                self.whitelist = strings();
                self.nodes.retain(|ip, _| !self.whitelist.contains(ip));
                self.edges
                    .retain(|_, e| !self.whitelist.contains(&e.target));
            }
            "watchlist" => self.watch = strings().into_iter().collect(),
            "interface" => {
                if let Some(name) = value.as_str() {
                    self.iface = name.into();
                }
            }
            _ => {}
        }
    }
    pub fn restore_devices(&mut self, devices: Vec<Value>) {
        for device in devices {
            let Some(ip) = device["ip"].as_str().and_then(|s| s.parse::<IpAddr>().ok()) else {
                continue;
            };
            if !private(ip) || self.local_ips.contains(&ip) {
                continue;
            }
            let mut node = self.node(ip);
            node.category = "lan_device".into();
            node.color = "#38bdf8".into();
            node.private = true;
            if let Some(host) = device["hostname"].as_str().filter(|s| !s.is_empty()) {
                node.label = host.into();
            }
            if let Some(extra) = device.as_object() {
                node.extra = extra.clone();
            }
            self.nodes.insert(ip.to_string(), node);
        }
    }
    pub fn learn_device(&mut self, ip: IpAddr, mac: Option<String>, hostname: Option<String>) {
        if !private(ip)
            || self.local_ips.contains(&ip)
            || noise(ip)
            || self.whitelist.contains(&ip.to_string())
        {
            return;
        }
        let id = ip.to_string();
        let new = !self.nodes.contains_key(&id);
        if new {
            if self.nodes.len() >= MAX_NODES {
                return;
            }
            self.nodes.insert(id.clone(), self.node(ip));
        }
        let n = self.nodes.get_mut(&id).unwrap();
        n.category = "lan_device".into();
        n.private = true;
        n.last = Instant::now();
        n.color = "#38bdf8".into();
        n.extra.insert("online".into(), json!(true));
        n.extra
            .insert("last_seen".into(), json!(Utc::now().to_rfc3339()));
        if !n.extra.contains_key("first_seen") {
            n.extra
                .insert("first_seen".into(), json!(Utc::now().to_rfc3339()));
        }
        if let Some(mac) = mac {
            let compact = mac.replace(':', "").to_uppercase();
            let (vendor, device_type) = crate::observer::vendor(&mac);
            if let Some(vendor) = vendor {
                n.extra.insert("vendor".into(), json!(vendor));
            }
            if let Some(device_type) = device_type {
                n.extra.insert("device_type".into(), json!(device_type));
            }
            n.extra.insert(
                "private_mac".into(),
                json!(compact
                    .get(..2)
                    .and_then(|s| u8::from_str_radix(s, 16).ok())
                    .is_some_and(|b| b & 2 != 0)),
            );
            n.extra.insert("mac".into(), json!(mac));
        }
        let hostname = hostname.or_else(|| {
            self.names
                .get(&ip)
                .map(|(n, _)| n.trim_end_matches(".local").to_string())
        });
        if let Some(host) = hostname.filter(|s| !s.is_empty() && s.len() <= 253) {
            n.label = host.clone();
            n.extra.insert("hostname".into(), json!(host));
        }
        self.dirty.insert(id.clone());
        if self.pending.devices.len() < MAX_NODES {
            self.pending.devices.insert(id.clone(), json!(n));
        }
        if new {
            self.alert(
                "NEW_LAN_DEVICE",
                &id,
                "info",
                format!("New LAN device: {id}"),
                json!({"ip":id}),
            );
        }
    }
    pub fn queue_block(&mut self, rule_id: &str, ip: &str) {
        let key = (rule_id.to_string(), ip.to_string());
        if self.rule_blocks.len() < 8192
            && self.firewall_actions.len() < 128
            && self.rule_blocks.insert(key)
        {
            self.firewall_actions
                .push_back(json!({"kind":"ip","value":ip,"action":"block","rule_id":rule_id}));
        }
    }
    pub fn learn_ptr(&mut self, ip: IpAddr, port: u16, proto: &str, hostname: Option<String>) {
        self.ptr_inflight.remove(&ip);
        if let Some(name) = hostname {
            if self.names.len() < MAX_NAMES && !self.names.contains_key(&ip) {
                self.names.insert(
                    ip,
                    (name.clone(), Instant::now() + Duration::from_secs(3600)),
                );
                self.ptr_named.insert(ip);
                let id = ip.to_string();
                if let Some(node) = self.nodes.get_mut(&id) {
                    node.label = name.clone();
                    let (category, color, _) = self.classifier.classify(&name, port, proto);
                    node.category = category.into();
                    node.color = color.into();
                    self.dirty.insert(id);
                }
            }
        } else {
            if self.ptr_failed.len() >= 4096 {
                self.ptr_failed
                    .retain(|_, at| at.elapsed() < Duration::from_secs(60));
            }
            if self.ptr_failed.len() < 4096 {
                self.ptr_failed.insert(ip, Instant::now());
            }
        }
    }
    pub fn clear_wire_frames(&mut self) {
        self.raw_frames.clear();
        self.raw_bytes = 0;
    }
    pub fn reload_geo(&mut self, data: &Path) {
        self.city = geodb::open(data.join("geo/dbip-city-lite.mmdb")).ok();
        self.asn = geodb::open(data.join("geo/dbip-asn-lite.mmdb")).ok();
    }
    pub fn init(&self) -> Value {
        let mut v = self.graph();
        v["type"] = json!("init");
        for (k, val) in self.status().as_object().unwrap() {
            v[k] = val.clone();
        }
        v["alerts"] = json!(self.alerts.iter().take(50).rev().collect::<Vec<_>>());
        v["media"] = self.media.clone();
        v
    }
    /// Disconnected clients get a complete snapshot on reconnect. Drop only
    /// transient delivery queues here; history, alerts and graph stay intact.
    pub fn discard_events(&mut self) {
        self.dirty.clear();
        self.events_packets.clear();
        self.events_alerts.clear();
        self.removed.clear();
    }
    pub fn drain_events(&mut self) -> Value {
        let dirty = std::mem::take(&mut self.dirty);
        let nodes: Vec<_> = self
            .nodes
            .iter()
            .filter(|(id, n)| dirty.contains(*id) && !n.private)
            .map(|(_, n)| n)
            .collect();
        let devices: Vec<_> = self
            .nodes
            .iter()
            .filter(|(id, n)| dirty.contains(*id) && n.private)
            .map(|(_, n)| n)
            .collect();
        json!({"type":"batch","nodes":nodes,"devices":devices,"edges":self.edges.values().filter(|e|dirty.contains(&e.target)).collect::<Vec<_>>(),"packets":std::mem::take(&mut self.events_packets),"alerts":std::mem::take(&mut self.events_alerts),"removed":std::mem::take(&mut self.removed)})
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn disconnected_delivery_preserves_reconnect_snapshot_and_history() {
        let mut e = Engine::new(
            Path::new("/nonexistent"),
            "test".into(),
            json!({}),
            vec![],
            HashSet::new(),
        );
        e.learn_device(
            "192.168.1.2".parse().unwrap(),
            Some("00:11:22:33:44:55".into()),
            Some("fixture".into()),
        );
        e.alert(
            "FIXTURE",
            "192.168.1.2",
            "warning",
            "fixture alert".into(),
            json!({}),
        );
        let snapshot = e.init();
        let history_count = e.pending.alerts.len();
        assert!(!e.dirty.is_empty());
        e.discard_events();
        assert_eq!(e.init(), snapshot);
        assert_eq!(e.pending.alerts.len(), history_count);
        assert!(
            e.dirty.is_empty()
                && e.events_packets.is_empty()
                && e.events_alerts.is_empty()
                && e.removed.is_empty()
        );
    }
    #[test]
    fn domain_suffix_boundaries() {
        let c = Classifier::new(Path::new("/nonexistent"));
        assert_eq!(c.classify("foo.doubleclick.net", 443, "TCP").0, "tracking");
        assert_eq!(c.classify("notdoubleclick.net", 443, "TCP").0, "safe");
        assert_eq!(c.classify("", 443, "UDP").2, "QUIC/HTTP3");
    }
    #[test]
    fn limits_and_status() {
        let e = Engine::new(
            Path::new("/nonexistent"),
            "test".into(),
            json!({}),
            vec![],
            HashSet::new(),
        );
        assert_eq!(e.graph()["nodes"].as_array().unwrap().len(), 1);
        assert_eq!(e.status()["capturing"], true);
    }
}
