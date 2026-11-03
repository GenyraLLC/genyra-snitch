//! Native bounded heuristic detector and online isolation forest.
use chrono::{Timelike, Utc};
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet, VecDeque};

#[derive(Clone, Debug)]
pub struct Finding {
    pub kind: &'static str,
    pub severity: &'static str,
    pub message: String,
    pub details: Value,
}
pub struct Context<'a> {
    pub ip: &'a str,
    pub host: &'a str,
    pub observed_host: bool,
    pub process: &'a str,
    pub country: &'a str,
    pub port: u16,
    pub proto: &'a str,
    pub out: bool,
    pub size: u32,
    pub now: f64,
    pub payload: &'a [u8],
    pub mic: bool,
    pub camera: bool,
}
#[derive(Default)]
struct Host {
    times: VecDeque<f64>,
    bytes: VecDeque<(i64, u64)>,
    baseline: VecDeque<u64>,
    fold: i64,
    icmp: (i64, u32),
}
#[derive(Default)]
pub struct Detector {
    hosts: HashMap<String, Host>,
    cool: HashMap<String, f64>,
    pub baselines: HashMap<String, Value>,
    forest: FlowModel,
    constants: Value,
}
impl Detector {
    pub fn new(baselines: &Value) -> Self {
        Self {
            baselines: baselines
                .as_object()
                .into_iter()
                .flatten()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect(),
            constants: serde_json::from_str(include_str!("../resources/detection-constants.json"))
                .unwrap(),
            ..Self::default()
        }
    }
    #[allow(clippy::too_many_arguments)] // Central finding builder with explicit cooldown policy.
    fn emit(
        &mut self,
        out: &mut Vec<Finding>,
        c: &Context<'_>,
        kind: &'static str,
        severity: &'static str,
        seconds: f64,
        key: String,
        message: String,
        details: Value,
    ) {
        let key = format!("{kind}:{key}");
        if self.cool.get(&key).is_some_and(|at| c.now - at < seconds) {
            return;
        }
        if self.cool.len() >= 16384 {
            self.cool.retain(|_, at| c.now - *at < 3600.);
            if self.cool.len() >= 16384 {
                return;
            }
        }
        self.cool.insert(key, c.now);
        out.push(Finding {
            kind,
            severity,
            message,
            details,
        });
    }
    pub fn observe(&mut self, c: Context<'_>) -> Vec<Finding> {
        let mut findings = Vec::new();
        if self.hosts.len() >= 4096 && !self.hosts.contains_key(c.ip) {
            self.hosts
                .retain(|_, h| h.times.back().is_some_and(|t| c.now - *t < 3600.));
            if self.hosts.len() >= 4096 {
                return findings;
            }
        }
        let host = self.hosts.entry(c.ip.into()).or_default();
        if host.times.len() >= 64 {
            host.times.pop_front();
        }
        host.times.push_back(c.now);
        let whitelist = self.constants["BEACON_WHITELIST"]
            .as_array()
            .is_some_and(|ips| ips.iter().any(|ip| ip == c.ip));
        let beacon = if !whitelist
            && host.times.len() >= 13
            && host.times.back().unwrap() - host.times.front().unwrap() >= 60.
        {
            let times: Vec<_> = host.times.iter().copied().collect();
            let intervals: Vec<_> = times.windows(2).map(|w| w[1] - w[0]).collect();
            let mean = intervals.iter().sum::<f64>() / intervals.len() as f64;
            let cv = (intervals.iter().map(|v| (v - mean).powi(2)).sum::<f64>()
                / intervals.len() as f64)
                .sqrt()
                / mean;
            if (1.0..=600.0).contains(&mean) && cv < 0.35 {
                Some((mean, cv, intervals.len()))
            } else {
                None
            }
        } else {
            None
        };
        let sec = c.now as i64;
        let mut volume = None;
        if c.out {
            while host.bytes.front().is_some_and(|(at, _)| *at + 60 < sec) {
                host.bytes.pop_front();
            }
            if host.bytes.back().is_some_and(|(at, _)| *at == sec) {
                host.bytes.back_mut().unwrap().1 += c.size as u64;
            } else {
                host.bytes.push_back((sec, c.size as u64));
            }
            let total = host.bytes.iter().map(|(_, b)| b).sum::<u64>();
            let mut baseline: Vec<_> = host.baseline.iter().copied().collect();
            baseline.sort_unstable();
            let med = if baseline.len() >= 3 {
                baseline[baseline.len() / 2]
            } else {
                0
            };
            if total > 5 * 1024 * 1024 && total > med * 5 {
                volume = Some((total, med));
            }
            if sec - host.fold >= 60 {
                host.fold = sec;
                if host.baseline.len() >= 32 {
                    host.baseline.pop_front();
                }
                host.baseline.push_back(total);
            }
        }
        let icmp = if c.proto.starts_with("ICMP")
            && c.payload.len() >= 32
            && c.payload
                .first()
                .is_some_and(|t| [0, 8, 13, 14, 128, 129].contains(t))
        {
            if sec - host.icmp.0 > 300 {
                host.icmp = (sec, 0);
            }
            host.icmp.1 += 1;
            host.icmp.1 == 3
        } else {
            false
        };
        if let Some((mean, cv, samples)) = beacon {
            self.emit(
                &mut findings,
                &c,
                "BEACON",
                "warning",
                300.,
                c.ip.into(),
                format!(
                    "Beacon-like regularity: ~{mean:.0}s interval to {} (CV {cv:.2})",
                    c.host
                ),
                json!({"ip":c.ip,"host":c.host,"interval_s":mean,"cv":cv,"samples":samples}),
            );
        }
        if let Some((bytes, baseline)) = volume {
            self.emit(&mut findings,&c,"VOLUME_SPIKE","warning",120.,c.ip.into(),format!("Data spike to {}: {} KB in 60s",c.host,bytes/1024),json!({"ip":c.ip,"host":c.host,"bytes":bytes,"baseline":baseline,"window_s":60,"process":c.process}));
        }
        if icmp {
            self.emit(
                &mut findings,
                &c,
                "ICMP_TUNNEL",
                "warning",
                300.,
                c.ip.into(),
                format!("Possible ICMP tunnelling involving {}", c.ip),
                json!({"ip":c.ip,"payload_len":c.payload.len().saturating_sub(8),"count_5m":3}),
            );
        }
        if let Some(hit) = if c.observed_host { dga(c.host) } else { None } {
            self.emit(
                &mut findings,
                &c,
                "DGA_SUSPECT",
                "info",
                3600.,
                c.host.into(),
                format!("DGA-looking domain {}", c.host),
                hit,
            );
        }
        if self.constants["SUSPICIOUS_PROCESSES"]
            .as_array()
            .is_some_and(|p| {
                p.iter().any(|p| {
                    p.as_str()
                        .is_some_and(|p| p.eq_ignore_ascii_case(c.process))
                })
            })
        {
            self.emit(
                &mut findings,
                &c,
                "SUSPICIOUS_PROCESS",
                "warning",
                300.,
                format!("{}:{}", c.process, c.ip),
                format!("Suspicious process {} contacted {}", c.process, c.host),
                json!({"process":c.process,"ip":c.ip,"host":c.host}),
            );
        }
        if c.out
            && (c.mic || c.camera)
            && !self.constants["MEDIA_WHITELIST"]
                .as_array()
                .is_some_and(|list| {
                    list.iter().any(|p| {
                        p.as_str()
                            .is_some_and(|p| p.eq_ignore_ascii_case(c.process))
                    })
                })
        {
            self.emit(&mut findings,&c,"MEDIA_EXFIL","critical",300.,format!("{}:{}",c.process,c.ip),format!("Suspected media exfiltration: {} → {}",c.process,c.host),json!({"process":c.process,"ip":c.ip,"host":c.host,"device":if c.mic{"microphone"}else{"camera"}}));
        }
        if c.out && c.proto == "TCP" {
            if let Some(service) = self.constants["CLEARTEXT_PORTS"][c.port.to_string()]
                .as_str()
                .map(str::to_string)
            {
                self.emit(&mut findings,&c,"CLEARTEXT","info",3600.,format!("{}:{}",c.ip,c.port),format!("Unencrypted {service} connection to {} by {}",c.host,c.process),json!({"ip":c.ip,"host":c.host,"port":c.port,"proto":service,"process":c.process}));
            }
        }
        if (c.port == 53 || c.port == 5353) && !c.payload.is_empty() {
            for (_, name, _) in crate::packet::dns(c.payload) {
                if name.len() > 60 || name.split('.').any(|l| l.len() > 40) {
                    self.emit(
                        &mut findings,
                        &c,
                        "DNS_TUNNEL",
                        "warning",
                        600.,
                        c.ip.into(),
                        format!("Possible DNS tunneling: oversized name {name}"),
                        json!({"ip":c.ip,"name":name,"process":c.process,"length":name.len()}),
                    );
                }
            }
        }
        let head = &c.payload[..c.payload.len().min(64)];
        let tls = head.starts_with(&[22, 3]) || head.starts_with(&[23, 3]);
        if c.proto == "TCP" && !tls && !head.is_empty() {
            if head.len() >= 48 && ![53, 853].contains(&c.port) {
                let ent = entropy(head);
                if ent >= 4.7 {
                    self.emit(
                        &mut findings,
                        &c,
                        "HIGH_ENTROPY",
                        "info",
                        600.,
                        c.ip.into(),
                        format!(
                            "High-entropy payload on cleartext channel {}:{}",
                            c.ip, c.port
                        ),
                        json!({"ip":c.ip,"port":c.port,"entropy":ent,"process":c.process}),
                    );
                }
            }
            let mismatch = match c.port {
                80 => {
                    head.len() >= 4
                        && !head.starts_with(b"HTTP")
                        && ![
                            b"GET ".as_slice(),
                            b"POST",
                            b"HEAD",
                            b"PUT ",
                            b"DELE",
                            b"OPTI",
                            b"PATC",
                            b"TRAC",
                            b"CONN",
                        ]
                        .iter()
                        .any(|m| head.starts_with(m))
                }
                22 => head.len() >= 4 && !head.starts_with(b"SSH-"),
                443 | 853 => head.len() >= 4 && !head.starts_with(&[21, 3]),
                21 | 25 | 110 | 143 | 587 => {
                    head.len() >= 4
                        && head
                            .iter()
                            .any(|b| !b.is_ascii() || (*b < 32 && !b"\r\n\t".contains(b)))
                }
                _ => false,
            };
            if mismatch {
                self.emit(
                    &mut findings,
                    &c,
                    "PROTO_MISMATCH",
                    "info",
                    600.,
                    format!("{}:{}", c.ip, c.port),
                    format!(
                        "Payload does not match protocol advertised by port {}",
                        c.port
                    ),
                    json!({"ip":c.ip,"port":c.port,"process":c.process}),
                );
            }
            let text = String::from_utf8_lossy(head).to_lowercase();
            if ["mining.", "\"blob\"", "\"job_id\"", "\"seed_hash\""]
                .iter()
                .any(|m| text.contains(m))
            {
                self.emit(&mut findings,&c,"MINING_SUSPECT","warning",600.,format!("{}:{}",c.process,c.ip),format!("Stratum-like mining protocol from {} to {}",c.process,c.ip),json!({"ip":c.ip,"process":c.process,"port":c.port,"reason":"strong stratum protocol marker"}));
            }
        }
        if !c.process.is_empty()
            && (self.baselines.len() < 2000 || self.baselines.contains_key(c.process))
        {
            let profile = self
                .baselines
                .entry(c.process.to_lowercase())
                .or_insert(json!({"countries":[],"ports":[],"seen":0}));
            let seen = profile["seen"].as_u64().unwrap_or(0) + 1;
            profile["seen"] = json!(seen);
            let mut countries = profile["countries"].as_array().cloned().unwrap_or_default();
            let fresh = !c.country.is_empty() && !countries.iter().any(|v| v == c.country);
            if fresh && countries.len() < 32 {
                countries.push(json!(c.country));
                profile["countries"] = json!(countries);
            }
            let mut ports = profile["ports"].as_array().cloned().unwrap_or_default();
            if c.port > 0 && ports.len() < 64 && !ports.iter().any(|p| p == c.port) {
                ports.push(json!(c.port));
                profile["ports"] = json!(ports);
            }
            if fresh && seen > 10 {
                self.emit(&mut findings,&c,"BASELINE_DEVIATION","warning",900.,format!("{}:{}",c.process,c.country),format!("{} contacted a new country: {}",c.process,c.country),json!({"ip":c.ip,"host":c.host,"process":c.process,"country":c.country,"known":countries}));
            }
        }
        if c.out {
            if let Some(score) = self.forest.observe(&c) {
                self.emit(&mut findings,&c,"ML_ANOMALY","warning",900.,format!("{}:{}",c.process,c.ip),format!("Isolation-forest score {score:.2} — flow unlike this host's learned baseline"),json!({"ip":c.ip,"process":c.process,"score":score}));
            }
        }
        findings
    }
}
fn entropy(s: &[u8]) -> f64 {
    if s.is_empty() {
        return 0.;
    }
    let mut counts = [0u32; 256];
    for b in s {
        counts[*b as usize] += 1;
    }
    counts
        .into_iter()
        .filter(|n| *n > 0)
        .map(|n| {
            let p = n as f64 / s.len() as f64;
            -p * p.log2()
        })
        .sum()
}
pub fn dga(name: &str) -> Option<Value> {
    let labels: Vec<_> = name.trim_end_matches('.').split('.').collect();
    if labels.len() < 2 || name.parse::<std::net::IpAddr>().is_ok() {
        return None;
    }
    let mut index = labels.len() - 2;
    if [
        "amazonaws",
        "azure",
        "cloudfront",
        "akamaized",
        "akamai",
        "akamaihd",
        "fastly",
        "cloudflare",
        "googleusercontent",
        "fbcdn",
        "edgesuite",
        "edgekey",
        "azurewebsites",
    ]
    .contains(&labels[index])
        && index > 0
    {
        index -= 1;
    }
    let label = labels[index].to_ascii_lowercase();
    let b = label.as_bytes();
    if b.len() < 10 {
        return None;
    }
    let ent = entropy(b);
    let vowels = b.iter().filter(|b| b"aeiou".contains(b)).count() as f64 / b.len() as f64;
    let digits = b.iter().filter(|b| b.is_ascii_digit()).count() as f64 / b.len() as f64;
    let mut run = 0;
    let mut best = 0;
    for c in b {
        if b"aeiou".contains(c) {
            run = 0;
        } else {
            run += 1;
            best = best.max(run);
        }
    }
    let mut reasons = Vec::new();
    if vowels < 0.15 {
        reasons.push("almost no vowels".to_string());
    }
    if best >= 5 {
        reasons.push(format!("{best}-consonant run"));
    }
    if digits > 0.2 {
        reasons.push("digit-heavy".into());
    }
    if labels.len() >= 4 {
        reasons.push("deeply nested".into());
    }
    let score = if ent >= 4. {
        1.
    } else if ent >= 3.4 && !reasons.is_empty() {
        if b.len() >= 20 {
            0.8
        } else {
            0.7
        }
    } else {
        return None;
    };
    reasons.insert(0, format!("entropy {ent:.1} bits/char"));
    Some(json!({"score":score,"entropy":ent,"label":label,"reasons":reasons,"name":name}))
}

type Features = [f64; 6];
enum Tree {
    Leaf(usize),
    Split {
        feature: usize,
        split: f64,
        left: Box<Tree>,
        right: Box<Tree>,
    },
}
#[allow(clippy::approx_constant)] // Match upstream isolation-forest normalization.
fn c(n: usize) -> f64 {
    if n <= 1 {
        1.
    } else {
        2. * ((n - 1) as f64).ln() + 2. * 0.5772156649 - 2. * (n - 1) as f64 / n as f64
    }
}
impl Tree {
    fn path(&self, x: &Features, depth: f64) -> f64 {
        match self {
            Self::Leaf(n) => depth + c(*n),
            Self::Split {
                feature,
                split,
                left,
                right,
            } => {
                if x[*feature] < *split {
                    left.path(x, depth + 1.)
                } else {
                    right.path(x, depth + 1.)
                }
            }
        }
    }
}
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn unit(&mut self) -> f64 {
        (self.next() >> 11) as f64 / (1u64 << 53) as f64
    }
}
#[derive(Default)]
struct FlowModel {
    window: VecDeque<Features>,
    trees: Vec<Tree>,
    since_fit: usize,
    seen: HashMap<(String, String, u16), f64>,
    fanout: HashMap<String, HashSet<String>>,
}
impl FlowModel {
    fn build(data: &[Features], depth: usize, rng: &mut Rng) -> Tree {
        if data.len() <= 1 || depth >= 8 {
            return Tree::Leaf(data.len());
        }
        let mut ranges = Vec::new();
        for f in 0..6 {
            let lo = data.iter().map(|x| x[f]).fold(f64::INFINITY, f64::min);
            let hi = data.iter().map(|x| x[f]).fold(f64::NEG_INFINITY, f64::max);
            if lo < hi {
                ranges.push((f, lo, hi));
            }
        }
        if ranges.is_empty() {
            return Tree::Leaf(data.len());
        }
        let (feature, lo, hi) = ranges[rng.next() as usize % ranges.len()];
        let split = lo + rng.unit() * (hi - lo);
        let (left, right): (Vec<_>, Vec<_>) =
            data.iter().copied().partition(|x| x[feature] < split);
        if left.is_empty() || right.is_empty() {
            Tree::Leaf(data.len())
        } else {
            Tree::Split {
                feature,
                split,
                left: Box::new(Self::build(&left, depth + 1, rng)),
                right: Box::new(Self::build(&right, depth + 1, rng)),
            }
        }
    }
    fn observe(&mut self, ctx: &Context<'_>) -> Option<f64> {
        let key = (ctx.process.to_string(), ctx.ip.to_string(), ctx.port);
        let prev = self.seen.get(&key).copied();
        let interval = prev
            .map(|v| (ctx.now - v).clamp(0., 3600.))
            .unwrap_or(3600.);
        if self.seen.len() < 4096 {
            self.seen.insert(key, ctx.now);
        }
        if self.fanout.len() < 4096 {
            let fan = self.fanout.entry(ctx.process.into()).or_default();
            if fan.len() < 512 {
                fan.insert(ctx.ip.into());
            }
        }
        let fan = self.fanout.get(ctx.process).map(HashSet::len).unwrap_or(0);
        let features = [
            ctx.port as f64 / 65535.,
            ctx.size.min(65535) as f64 / 65535.,
            interval.ln_1p() / 3600f64.ln_1p(),
            fan.min(512) as f64 / 512.,
            Utc::now().hour() as f64 / 23.,
            1.,
        ];
        if self.window.len() >= 4096 {
            self.window.pop_front();
        }
        self.window.push_back(features);
        self.since_fit += 1;
        if self.since_fit >= 256 {
            let data: Vec<_> = self.window.iter().copied().collect();
            let mut rng = Rng(20261022 + self.window.len() as u64);
            self.trees.clear();
            for _ in 0..64 {
                let mut indices: Vec<_> = (0..data.len()).collect();
                let count = indices.len().min(256);
                for i in 0..count {
                    let j = i + rng.next() as usize % (indices.len() - i);
                    indices.swap(i, j);
                }
                let sample: Vec<_> = indices.into_iter().take(count).map(|i| data[i]).collect();
                self.trees.push(Self::build(&sample, 0, &mut rng));
            }
            self.since_fit = 0;
        }
        if self.window.len() < 384 || self.trees.is_empty() {
            return None;
        }
        let path = self
            .trees
            .iter()
            .map(|t| t.path(&features, 0.))
            .sum::<f64>()
            / self.trees.len() as f64;
        let score = 2f64.powf(-path / c(256));
        if score >= 0.62 {
            Some(score)
        } else {
            None
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn context<'a>(ip: &'a str, time: f64) -> Context<'a> {
        Context {
            ip,
            host: ip,
            observed_host: true,
            process: "test",
            country: "US",
            port: 443,
            proto: "TCP",
            out: true,
            size: 64,
            now: time,
            payload: &[],
            mic: false,
            camera: false,
        }
    }
    #[test]
    fn dga_and_legitimate_names() {
        assert!(dga("xj3kq9zwvbt.test").is_some());
        assert!(dga("duckduckgo.com").is_none());
        assert!(dga("192.168.1.1").is_none());
    }
    #[test]
    fn beacon_min_span_and_cooldown() {
        let mut d = Detector::new(&json!({}));
        let mut hits = 0;
        for i in 0..13 {
            hits += d
                .observe(context("198.51.100.5", 1000. + i as f64 * 5.))
                .iter()
                .filter(|f| f.kind == "BEACON")
                .count();
        }
        assert_eq!(hits, 1);
        assert!(!d
            .observe(context("198.51.100.5", 1065.))
            .iter()
            .any(|f| f.kind == "BEACON"));
    }
    #[test]
    fn forest_training_warmup() {
        let mut model = FlowModel::default();
        for i in 0..383 {
            assert!(model.observe(&context("198.51.100.1", i as f64)).is_none());
        }
    }
}
#[cfg(test)]
mod behavior_tests {
    use super::*;
    #[test]
    fn learned_model_flags_a_large_rare_flow() {
        let mut model = FlowModel::default();
        for i in 0..1000 {
            let c = Context {
                ip: "198.51.100.1",
                host: "fixture.example",
                observed_host: true,
                process: "fixture",
                country: "US",
                port: if i % 2 == 0 { 443 } else { 80 },
                proto: "TCP",
                out: true,
                size: 200 + (i % 70),
                now: 1000. + i as f64 * 0.1,
                payload: &[],
                mic: false,
                camera: false,
            };
            model.observe(&c);
        }
        let c = Context {
            ip: "198.51.100.99",
            host: "rare.example",
            observed_host: true,
            process: "fixture",
            country: "US",
            port: 65000,
            proto: "TCP",
            out: true,
            size: 65000,
            now: 5000.,
            payload: &[],
            mic: false,
            camera: false,
        };
        assert!(
            model.observe(&c).is_some(),
            "A rare large flow must be distinguishable from the learned small-flow baseline"
        );
    }
}
