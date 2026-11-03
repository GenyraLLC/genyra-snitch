//! Packet-side policy visibility. OS enforcement is performed separately.
use serde_json::{json, Value};
use std::net::IpAddr;
#[derive(Default)]
pub struct Policy {
    lockdown: bool,
    entries: Vec<(Value, Matcher)>,
}
enum Matcher {
    Nets(Vec<ipnet::IpNet>),
    Domain(String, Vec<ipnet::IpNet>),
    Port(u16),
    Process(String),
}
impl Policy {
    pub fn new(settings: &Value) -> Self {
        let entries = settings["firewall_rules"]
            .as_array()
            .into_iter()
            .flatten()
            .take(5000)
            .filter(|r| r["enabled"] != false)
            .filter_map(|r| {
                let v = r["value"].as_str()?;
                let nets = |v: &str| {
                    v.parse::<ipnet::IpNet>()
                        .ok()
                        .or_else(|| v.parse::<IpAddr>().ok().map(ipnet::IpNet::from))
                };
                let m = match r["kind"].as_str()? {
                    "ip" | "cidr" => Matcher::Nets(vec![nets(v)?]),
                    "domain" => Matcher::Domain(
                        v.to_lowercase(),
                        r["resolved"]
                            .as_array()
                            .into_iter()
                            .flatten()
                            .filter_map(|v| v.as_str().and_then(nets))
                            .collect(),
                    ),
                    "port" => Matcher::Port(v.parse().ok()?),
                    "process" => Matcher::Process(v.to_lowercase()),
                    _ => return None,
                };
                Some((r.clone(), m))
            })
            .collect();
        Self {
            lockdown: settings["firewall_lockdown"] == true,
            entries,
        }
    }
    pub fn matching(
        &self,
        ip: IpAddr,
        port: u16,
        host: &str,
        process: &str,
        out: bool,
    ) -> Option<Value> {
        if self.lockdown && out && !crate::state::private(ip) {
            return Some(
                json!({"id":"__lockdown__","kind":"lockdown","value":"*","action":"block"}),
            );
        }
        let host = host.to_ascii_lowercase();
        let process = process.to_lowercase();
        self.entries
            .iter()
            .find(|(_, m)| match m {
                Matcher::Nets(n) => n.iter().any(|n| n.contains(&ip)),
                Matcher::Domain(d, n) => {
                    host == *d
                        || host.ends_with(&format!(".{d}"))
                        || n.iter().any(|n| n.contains(&ip))
                }
                Matcher::Port(p) => *p == port,
                Matcher::Process(p) => {
                    process == *p
                        || process.ends_with(&format!("/{p}"))
                        || process.ends_with(&format!("\\{p}"))
                }
            })
            .map(|(r, _)| r.clone())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn cidr_domain_process_and_lockdown() {
        let p = Policy::new(
            &json!({"firewall_rules":[{"id":"net","kind":"cidr","value":"8.8.0.0/16"},{"id":"host","kind":"domain","value":"example.com"},{"id":"app","kind":"process","value":"curl"}]}),
        );
        assert_eq!(
            p.matching("8.8.8.8".parse().unwrap(), 443, "", "", true)
                .unwrap()["id"],
            "net"
        );
        assert_eq!(
            p.matching("1.1.1.1".parse().unwrap(), 443, "api.example.com", "", true)
                .unwrap()["id"],
            "host"
        );
        assert!(p
            .matching(
                "1.1.1.1".parse().unwrap(),
                443,
                "evil-example.com",
                "",
                true
            )
            .is_none());
        assert_eq!(
            p.matching("1.1.1.1".parse().unwrap(), 443, "", "/usr/bin/CURL", true)
                .unwrap()["id"],
            "app"
        );
        let p = Policy::new(&json!({"firewall_lockdown":true}));
        assert!(p
            .matching("192.168.1.1".parse().unwrap(), 443, "", "", true)
            .is_none());
        assert!(p
            .matching("1.1.1.1".parse().unwrap(), 443, "", "", false)
            .is_none());
    }
}
