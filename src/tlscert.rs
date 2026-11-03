//! Passive TLS 1.2 leaf inspection. TLS 1.3 encrypted certificates remain unknown.
use serde_json::{json, Value};
use std::{
    collections::HashMap,
    net::IpAddr,
    time::{Duration, Instant},
};
type Key = (IpAddr, u16, IpAddr, u16);
#[derive(Default)]
pub struct Inspector {
    flows: HashMap<Key, (Vec<u8>, Instant, u32)>,
}
impl Inspector {
    pub fn feed(&mut self, p: &crate::packet::Packet<'_>) -> Option<Value> {
        if p.proto != "TCP"
            || p.payload.is_empty()
            || ![443, 853, 465, 587, 636, 993, 995, 989, 990, 8443, 9443].contains(&p.sport)
        {
            return None;
        }
        let key = (p.src, p.sport, p.dst, p.dport);
        if self.flows.len() >= 256 {
            self.flows
                .retain(|_, (_, at, _)| at.elapsed() < Duration::from_secs(30));
            if self.flows.len() >= 256 {
                let old = self
                    .flows
                    .iter()
                    .min_by_key(|(_, (_, at, _))| *at)
                    .map(|(k, _)| *k)?;
                self.flows.remove(&old);
            }
        }
        if let std::collections::hash_map::Entry::Vacant(entry) = self.flows.entry(key) {
            if !p.payload.starts_with(b"\x16\x03") {
                return None;
            }
            entry.insert((Vec::new(), Instant::now(), p.sequence));
        }
        let (buffer, at, next) = self.flows.get_mut(&key)?;
        let overlap = next.wrapping_sub(p.sequence) as usize;
        if overlap > p.payload.len() {
            self.flows.remove(&key);
            return None;
        }
        let tail = &p.payload[overlap..];
        if buffer.len() + tail.len() > 16384 {
            self.flows.remove(&key);
            return None;
        }
        buffer.extend_from_slice(tail);
        *next = next.wrapping_add(tail.len() as u32);
        *at = Instant::now();
        let result = certificate(buffer);
        if result.is_some() {
            self.flows.remove(&key);
        }
        result
    }
}
fn n24(b: &[u8]) -> Option<usize> {
    Some(
        ((u32::from(*b.first()?) << 16) | (u32::from(*b.get(1)?) << 8) | u32::from(*b.get(2)?))
            as usize,
    )
}
fn certificate(buffer: &[u8]) -> Option<Value> {
    let mut pos = 0;
    let mut hs = Vec::new();
    while pos + 5 <= buffer.len() {
        let size = u16::from_be_bytes([buffer[pos + 3], buffer[pos + 4]]) as usize;
        let record = buffer.get(pos + 5..pos + 5 + size)?;
        if buffer[pos] == 22 {
            hs.extend_from_slice(record);
        }
        pos += 5 + size;
    }
    pos = 0;
    while pos + 4 <= hs.len() {
        let kind = hs[pos];
        let size = n24(&hs[pos + 1..])?;
        let body = hs.get(pos + 4..pos + 4 + size)?;
        if kind == 11 {
            let len = n24(body.get(3..)?)?;
            return leaf(body.get(6..6 + len)?);
        }
        pos += 4 + size;
    }
    None
}
// Return tag, content, and the original DER slice. Reject indefinite lengths,
// integer overflow and non-minimal lengths before walking untrusted bytes.
fn tlv<'a>(b: &'a [u8], pos: &mut usize) -> Option<(u8, &'a [u8], &'a [u8])> {
    let start = *pos;
    let tag = *b.get(*pos)?;
    *pos += 1;
    let first = *b.get(*pos)?;
    *pos += 1;
    let len = if first & 128 == 0 {
        first as usize
    } else {
        let n = (first & 127) as usize;
        if n == 0 || n > 4 {
            return None;
        }
        let bytes = b.get(*pos..*pos + n)?;
        if bytes.first() == Some(&0) {
            return None;
        }
        *pos += n;
        bytes.iter().fold(0usize, |v, b| (v << 8) | *b as usize)
    };
    let end = pos.checked_add(len)?;
    let value = b.get(*pos..end)?;
    *pos = end;
    Some((tag, value, b.get(start..end)?))
}
fn name(b: &[u8]) -> Option<(String, String)> {
    let mut p = 0;
    let (_, seq, _) = tlv(b, &mut p)?;
    let mut p = 0;
    let mut cn = String::new();
    let mut org = String::new();
    while p < seq.len() {
        let (_, rdn, _) = tlv(seq, &mut p)?;
        let mut q = 0;
        while q < rdn.len() {
            let (_, attr, _) = tlv(rdn, &mut q)?;
            let mut r = 0;
            let (_, oid, _) = tlv(attr, &mut r)?;
            let (_, text, _) = tlv(attr, &mut r)?;
            let text = String::from_utf8_lossy(text).chars().take(253).collect();
            match oid {
                [85, 4, 3] => cn = text,
                [85, 4, 10] => org = text,
                _ => {}
            }
        }
    }
    Some((cn, org))
}
fn leaf(der: &[u8]) -> Option<Value> {
    let mut p = 0;
    let (tag, cert, _) = tlv(der, &mut p)?;
    if tag != 48 {
        return None;
    }
    let mut p = 0;
    let (_, tbs, _) = tlv(cert, &mut p)?;
    let mut p = 0;
    let (tag, _, _) = tlv(tbs, &mut p)?;
    if tag == 160 {
        tlv(tbs, &mut p)?;
    }
    tlv(tbs, &mut p)?;
    let (_, _, issuer) = tlv(tbs, &mut p)?;
    let (_, validity, _) = tlv(tbs, &mut p)?;
    let (_, _, subject) = tlv(tbs, &mut p)?;
    tlv(tbs, &mut p)?;
    let (issuer_cn, issuer_o) = name(issuer)?;
    let (subject_cn, subject_o) = name(subject)?;
    let mut v = 0;
    let (_, before, _) = tlv(validity, &mut v)?;
    let (_, after, _) = tlv(validity, &mut v)?;
    let mut sans = Vec::new();
    while p < tbs.len() {
        let (tag, ext, _) = tlv(tbs, &mut p)?;
        if tag != 163 {
            continue;
        }
        let mut q = 0;
        let (_, exts, _) = tlv(ext, &mut q)?;
        let mut q = 0;
        while q < exts.len() {
            let (_, ext, _) = tlv(exts, &mut q)?;
            let mut r = 0;
            let (_, oid, _) = tlv(ext, &mut r)?;
            if oid != [85, 29, 17] {
                continue;
            }
            let (tag, mut val, _) = tlv(ext, &mut r)?;
            if tag == 1 {
                val = tlv(ext, &mut r)?.1;
            }
            let mut z = 0;
            let (_, names, _) = tlv(val, &mut z)?;
            let mut z = 0;
            while z < names.len() {
                let (tag, val, _) = tlv(names, &mut z)?;
                if tag == 130 && val.len() <= 253 && sans.len() < 24 {
                    sans.push(String::from_utf8_lossy(val).to_string());
                }
            }
        }
    }
    Some(
        json!({"issuer_cn":issuer_cn,"issuer_o":issuer_o,"subject_cn":subject_cn,"subject_o":subject_o,"self_signed":issuer==subject,"sans":sans,"not_before":String::from_utf8_lossy(before),"not_after":String::from_utf8_lossy(after)}),
    )
}
pub fn mismatch(host: &str, sans: &Value) -> bool {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    if host.is_empty() {
        return false;
    }
    let Some(names) = sans.as_array().filter(|v| !v.is_empty()) else {
        return false;
    };
    !names.iter().filter_map(Value::as_str).any(|pat| {
        let pat = pat.trim_end_matches('.').to_ascii_lowercase();
        pat == host
            || pat.strip_prefix("*.").is_some_and(|suffix| {
                host.strip_suffix(&format!(".{suffix}"))
                    .is_some_and(|prefix| !prefix.is_empty() && !prefix.contains('.'))
            })
    })
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn wildcards_cover_one_label() {
        assert!(!mismatch("api.example.com", &json!(["*.example.com"])));
        assert!(mismatch("deep.api.example.com", &json!(["*.example.com"])));
        assert!(mismatch("example.com", &json!(["*.example.com"])));
    }
    #[test]
    fn malformed_der_and_records_never_panic() {
        let mut seed = 17u32;
        for n in 0..4096 {
            let b = (0..n % 512)
                .map(|_| {
                    seed = seed.wrapping_mul(1664525).wrapping_add(1013904223);
                    (seed >> 24) as u8
                })
                .collect::<Vec<_>>();
            let _ = certificate(&b);
            let _ = leaf(&b);
        }
    }
}
#[cfg(test)]
mod fixture_tests {
    use super::*;
    #[test]
    fn parses_public_self_signed_leaf_and_fragmented_records() {
        let der = include_bytes!("../tests/fixtures/leaf.der");
        let v = leaf(der).unwrap();
        assert_eq!(v["subject_cn"], "fixture.example");
        assert_eq!(v["self_signed"], true);
        assert_eq!(v["sans"], json!(["fixture.example", "*.example.test"]));
        fn n24(v: usize) -> [u8; 3] {
            [(v >> 16) as u8, (v >> 8) as u8, v as u8]
        }
        let mut body = Vec::new();
        body.extend(n24(der.len() + 3));
        body.extend(n24(der.len()));
        body.extend(der);
        let mut hs = vec![11];
        hs.extend(n24(body.len()));
        hs.extend(body);
        let mut wire = vec![22, 3, 3];
        wire.extend((hs.len() as u16).to_be_bytes());
        wire.extend(hs);
        assert_eq!(certificate(&wire).unwrap()["subject_cn"], "fixture.example");
        let mut inspector = Inspector::default();
        let mut p = crate::packet::Packet {
            src: "1.1.1.1".parse().unwrap(),
            dst: "192.168.1.2".parse().unwrap(),
            sport: 443,
            dport: 12345,
            proto: "TCP",
            sequence: 100,
            flags: 16,
            payload: &wire[..15],
        };
        assert!(inspector.feed(&p).is_none());
        p.payload = &wire[15..];
        p.sequence = 115;
        assert!(inspector.feed(&p).is_some());
    }
}
