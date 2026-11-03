//! Bounded passive parsers. Never resolve names or allocate from wire lengths.
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[derive(Debug)]
pub struct Packet<'a> {
    pub src: IpAddr,
    pub dst: IpAddr,
    pub sport: u16,
    pub dport: u16,
    pub proto: &'static str,
    pub flags: u16,
    pub sequence: u32,
    pub payload: &'a [u8],
}

fn u16be(b: &[u8], n: usize) -> Option<u16> {
    Some(u16::from_be_bytes(b.get(n..n + 2)?.try_into().ok()?))
}

pub fn parse(b: &[u8], link: i32) -> Option<Packet<'_>> {
    let (mut offset, mut kind) = match link {
        1 => (14, u16be(b, 12)?),   // Ethernet
        113 => (16, u16be(b, 14)?), // Linux cooked v1
        276 => (20, u16be(b, 0)?),  // Linux cooked v2
        12 | 101 => (0, if b.first()? >> 4 == 4 { 0x800 } else { 0x86dd }),
        _ => return None,
    };
    for _ in 0..2 {
        if kind != 0x8100 && kind != 0x88a8 {
            break;
        }
        kind = u16be(b, offset + 2)?;
        offset += 4;
    }
    let b = b.get(offset..)?;
    let (src, dst, mut next, mut pos, end) = if kind == 0x800 {
        if b.first()? >> 4 != 4 {
            return None;
        }
        let ihl = (b[0] & 15) as usize * 4;
        let total = u16be(b, 2)? as usize;
        if ihl < 20 || total < ihl || u16be(b, 6)? & 0x1fff != 0 {
            return None;
        }
        (
            IpAddr::V4(Ipv4Addr::from(<[u8; 4]>::try_from(b.get(12..16)?).ok()?)),
            IpAddr::V4(Ipv4Addr::from(<[u8; 4]>::try_from(b.get(16..20)?).ok()?)),
            *b.get(9)?,
            ihl,
            total.min(b.len()),
        )
    } else if kind == 0x86dd {
        if b.first()? >> 4 != 6 {
            return None;
        }
        (
            IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(b.get(8..24)?).ok()?)),
            IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(b.get(24..40)?).ok()?)),
            *b.get(6)?,
            40,
            (40 + u16be(b, 4)? as usize).min(b.len()),
        )
    } else {
        return None;
    };
    let b = b.get(..end)?;
    // IPv6 extension chain: reject noninitial fragments and cap work.
    for _ in 0..8 {
        let len = match next {
            0 | 43 | 60 => (*b.get(pos + 1)? as usize + 1) * 8,
            44 => {
                if u16be(b, pos + 2)? & 0xfff8 != 0 {
                    return None;
                }
                8
            }
            51 => (*b.get(pos + 1)? as usize + 2) * 4,
            _ => break,
        };
        next = *b.get(pos)?;
        pos += len;
        if pos > b.len() {
            return None;
        }
    }
    let (sport, dport, proto, start, end) = match next {
        6 => {
            let len = (*b.get(pos + 12)? >> 4) as usize * 4;
            if len < 20 {
                return None;
            }
            (
                u16be(b, pos)?,
                u16be(b, pos + 2)?,
                "TCP",
                pos + len,
                b.len(),
            )
        }
        17 => {
            let len = u16be(b, pos + 4)? as usize;
            if len < 8 {
                return None;
            }
            (
                u16be(b, pos)?,
                u16be(b, pos + 2)?,
                "UDP",
                pos + 8,
                (pos + len).min(b.len()),
            )
        }
        1 => (0, 0, "ICMP", pos, b.len()),
        58 => (0, 0, "ICMPv6", pos, b.len()),
        _ => return None,
    };
    Some(Packet {
        src,
        dst,
        sport,
        dport,
        proto,
        sequence: if next == 6 {
            u32::from_be_bytes(b.get(pos + 4..pos + 8)?.try_into().ok()?)
        } else {
            0
        },
        flags: if next == 6 {
            *b.get(pos + 13)? as u16
        } else {
            0
        },
        payload: b.get(start..end)?,
    })
}

pub(crate) fn dns_name(b: &[u8], cursor: &mut usize) -> Option<String> {
    let mut pos = *cursor;
    let mut jumped = false;
    let mut name = String::new();
    for _ in 0..64 {
        let len = *b.get(pos)? as usize;
        if len & 0xc0 == 0xc0 {
            let ptr = (u16be(b, pos)? & 0x3fff) as usize;
            if !jumped {
                *cursor = pos + 2;
                jumped = true;
            }
            pos = ptr;
        } else if len == 0 {
            if !jumped {
                *cursor = pos + 1;
            }
            return Some(name.to_ascii_lowercase());
        } else {
            if len > 63 || name.len() + len + 1 > 253 {
                return None;
            }
            let label = b.get(pos + 1..pos + 1 + len)?;
            if !label
                .iter()
                .all(|c| c.is_ascii_alphanumeric() || b"-_".contains(c))
            {
                return None;
            }
            if !name.is_empty() {
                name.push('.');
            }
            name.push_str(std::str::from_utf8(label).ok()?);
            pos += len + 1;
        }
    }
    None
}

/// Only learn A/AAAA answers actually observed on the wire. TTL is honored.
pub fn dns(b: &[u8]) -> Vec<(IpAddr, String, u32)> {
    let mut out = Vec::new();
    let Some(flags) = u16be(b, 2) else {
        return out;
    };
    if flags & 0x800f != 0x8000 {
        return out;
    }
    let Some(q) = u16be(b, 4) else {
        return out;
    };
    let Some(a) = u16be(b, 6) else {
        return out;
    };
    if q > 64 {
        return out;
    }
    let mut pos = 12;
    for _ in 0..q {
        if dns_name(b, &mut pos).is_none() {
            return out;
        }
        pos += 4;
    }
    for _ in 0..a.min(128) {
        let Some(name) = dns_name(b, &mut pos) else {
            break;
        };
        let Some(kind) = u16be(b, pos) else {
            break;
        };
        let Some(class) = u16be(b, pos + 2) else {
            break;
        };
        let Some(ttl) = b
            .get(pos + 4..pos + 8)
            .and_then(|v| v.try_into().ok())
            .map(u32::from_be_bytes)
        else {
            break;
        };
        let Some(len) = u16be(b, pos + 8) else {
            break;
        };
        pos += 10;
        let Some(data) = b.get(pos..pos + len as usize) else {
            break;
        };
        let ip = match (kind, data.len()) {
            (1, 4) => Some(IpAddr::V4(Ipv4Addr::from(
                <[u8; 4]>::try_from(data).unwrap(),
            ))),
            (28, 16) => Some(IpAddr::V6(Ipv6Addr::from(
                <[u8; 16]>::try_from(data).unwrap(),
            ))),
            _ => None,
        };
        if class & 0x7fff == 1 && ttl > 0 {
            if let Some(ip) = ip {
                out.push((ip, name.to_ascii_lowercase(), ttl.min(86400)));
            }
        }
        pos += len as usize;
    }
    out
}

/// Passive SNI from a complete TLS ClientHello in one TCP segment.
pub fn sni(b: &[u8]) -> Option<String> {
    if *b.first()? != 22 {
        return None;
    }
    let record = b.get(5..5 + u16be(b, 3)? as usize)?;
    if *record.first()? != 1 {
        return None;
    }
    let len = ((*record.get(1)? as usize) << 16)
        | ((*record.get(2)? as usize) << 8)
        | *record.get(3)? as usize;
    let b = record.get(4..4 + len)?;
    let mut p = 34;
    p += 1 + *b.get(p)? as usize;
    p += 2 + u16be(b, p)? as usize;
    p += 1 + *b.get(p)? as usize;
    let end = p + 2 + u16be(b, p)? as usize;
    p += 2;
    let b = b.get(..end)?;
    for _ in 0..128 {
        if p >= end {
            break;
        }
        let kind = u16be(b, p)?;
        let size = u16be(b, p + 2)? as usize;
        let data = b.get(p + 4..p + 4 + size)?;
        if kind == 0 {
            let list = data.get(2..2 + u16be(data, 0)? as usize)?;
            let mut n = 0;
            while n < list.len() {
                let len = u16be(list, n + 1)? as usize;
                let name = list.get(n + 3..n + 3 + len)?;
                if list[n] == 0
                    && len > 0
                    && len <= 253
                    && name
                        .iter()
                        .all(|c| c.is_ascii_alphanumeric() || b".-_".contains(c))
                {
                    return Some(std::str::from_utf8(name).ok()?.to_ascii_lowercase());
                }
                n += 3 + len;
            }
        }
        p += 4 + size;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    fn frame() -> Vec<u8> {
        let mut b = vec![0u8; 14 + 20 + 8 + 2];
        b[12..14].copy_from_slice(&0x800u16.to_be_bytes());
        b[14] = 0x45;
        b[16..18].copy_from_slice(&30u16.to_be_bytes());
        b[23] = 17;
        b[26..30].copy_from_slice(&[192, 168, 1, 2]);
        b[30..34].copy_from_slice(&[8, 8, 8, 8]);
        b[34..36].copy_from_slice(&12345u16.to_be_bytes());
        b[36..38].copy_from_slice(&53u16.to_be_bytes());
        b[38..40].copy_from_slice(&10u16.to_be_bytes());
        b
    }
    #[test]
    fn ethernet_and_vlan() {
        let mut b = frame();
        let p = parse(&b, 1).unwrap();
        assert_eq!(p.src.to_string(), "192.168.1.2");
        assert_eq!(p.dport, 53);
        assert_eq!(p.payload.len(), 2);
        b.splice(12..14, [0x81, 0, 0, 1, 8, 0]);
        assert!(parse(&b, 1).is_some());
    }
    #[test]
    fn fragments_and_truncation() {
        let b = frame();
        for n in 0..42 {
            assert!(parse(&b[..n], 1).is_none());
        }
        let mut b = b;
        b[21] = 1;
        assert!(parse(&b, 1).is_none());
    }
    #[test]
    fn dns_compression_and_loop() {
        let b=b"\x00\x01\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04\x08\x08\x08\x08";
        assert_eq!(
            dns(b),
            vec![("8.8.8.8".parse().unwrap(), "example.com".into(), 60)]
        );
        let mut p = 0;
        assert!(dns_name(&[0xc0, 0], &mut p).is_none());
    }
    #[test]
    fn arbitrary_input_never_panics() {
        let mut seed = 17u32;
        for n in 0..2000 {
            let b: Vec<u8> = (0..n % 512)
                .map(|_| {
                    seed = seed.wrapping_mul(1664525).wrapping_add(1013904223);
                    (seed >> 24) as u8
                })
                .collect();
            for link in [1, 113, 276, 101] {
                let _ = parse(&b, link);
            }
            let _ = dns(&b);
            let _ = sni(&b);
        }
    }
}
