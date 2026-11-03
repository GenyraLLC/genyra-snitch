use serde_json::Value;
use std::{collections::HashSet, net::IpAddr};
pub fn public(ip: IpAddr) -> bool {
    if crate::state::private(ip) || ip.is_unspecified() || ip.is_multicast() {
        return false;
    }
    match ip {
        IpAddr::V4(v) => {
            let b = v.octets();
            !v.is_documentation()
                && !v.is_broadcast()
                && b[0] != 0
                && b[0] < 224
                && !(b[0] == 198 && (b[1] == 18 || b[1] == 19))
                && !(b[0] == 192 && b[1] == 0 && b[2] == 0)
        }
        IpAddr::V6(v) => {
            let b = v.octets();
            !(b[..4] == [0x20, 1, 0x0d, 0xb8] || b[..8] == [1, 0, 0, 0, 0, 0, 0, 0])
        }
    }
}
fn domain(value: &str) -> bool {
    if value.len() > 253 || value.ends_with(".localhost") {
        return false;
    }
    let labels: Vec<_> = value.split('.').collect();
    if labels.len() < 2 {
        return false;
    }
    let tld = labels.last().unwrap();
    if !(2..=63).contains(&tld.len()) || !tld.bytes().all(|b| b.is_ascii_alphabetic()) {
        return false;
    }
    labels.iter().all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && label
                .as_bytes()
                .first()
                .is_some_and(u8::is_ascii_alphanumeric)
            && label
                .as_bytes()
                .last()
                .is_some_and(u8::is_ascii_alphanumeric)
            && label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
    })
}
pub fn parse(text: &str, kind: &str) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        if kind == "domain" {
            let parts: Vec<_> = line.split_whitespace().collect();
            let candidates = if parts.len() > 1 && parts[0].parse::<IpAddr>().is_ok() {
                &parts[1..]
            } else {
                &parts[..1]
            };
            for candidate in candidates {
                let value = candidate
                    .to_ascii_lowercase()
                    .trim_end_matches('.')
                    .to_string();
                if domain(&value) && seen.insert(value.clone()) {
                    out.push(value);
                }
            }
        } else {
            let token = line.split([',', ';', ' ', '\t']).next().unwrap_or("");
            if let Ok(net) = token.parse::<ipnet::IpNet>() {
                let bits = if net.addr().is_ipv4() { 32 } else { 128 };
                if bits - net.prefix_len() > 12 {
                    continue;
                }
                for ip in net.hosts().take(4096) {
                    let value = ip.to_string();
                    if public(ip) && seen.insert(value.clone()) {
                        out.push(value);
                        if out.len() >= 20000 {
                            return out;
                        }
                    }
                }
            } else if let Ok(ip) = token.parse::<IpAddr>() {
                let value = ip.to_string();
                if public(ip) && seen.insert(value.clone()) {
                    out.push(value);
                }
            }
        }
        if out.len() >= 20000 {
            break;
        }
    }
    out
}
pub fn existing(rules: &[Value], kind: &str, value: &str, action: &str) -> bool {
    rules.iter().any(|r| {
        r["kind"] == kind
            && r["value"]
                .as_str()
                .is_some_and(|v| v.eq_ignore_ascii_case(value))
            && r["action"].as_str().unwrap_or("block") == action
    })
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn hosts_aliases_and_deduplication() {
        assert_eq!(
            parse(
                "# hi\n0.0.0.0 example.com ads.example.com\nEXAMPLE.COM\nlocalhost\nnot_domain\n",
                "domain"
            ),
            vec!["example.com", "ads.example.com"]
        );
    }
    #[test]
    fn ip_feeds_skip_private_reserved_and_giant_subnets() {
        assert_eq!(
            parse(
                "8.8.8.8,443\n10.0.0.1\n192.0.2.2\n127.0.0.1\n8.8.8.8\n8.0.0.0/8\n",
                "ip"
            ),
            vec!["8.8.8.8"]
        );
    }
}
