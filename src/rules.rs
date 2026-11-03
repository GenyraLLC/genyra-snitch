//! Bounded Sigma subset import and YARA-L export using native YAML parsing.
use serde_json::{json, Value};

fn field(name: &str) -> Option<&'static str> {
    let n = name.to_ascii_lowercase().replace(['_', '.', '-', ' '], "");
    Some(match n.as_str() {
        "destinationip" | "dstip" => "remote_ip",
        "destinationport" | "dstport" => "remote_port",
        "image" | "processname" | "originalfilename" => "process_name",
        "destinationhostname"
        | "destinationhost"
        | "domain"
        | "hostname"
        | "host"
        | "queryname"
        | "sni"
        | "tlsservername"
        | "dnsquery" => "host",
        "protocol" | "ipprotocol" => "protocol",
        "destinationasn" | "asn" => "asn",
        "destinationcountry" | "country" => "country",
        _ => return None,
    })
}
fn text(v: &Value) -> String {
    v.as_str()
        .map(str::to_string)
        .unwrap_or_else(|| v.to_string())
}
fn clause(key: &str, v: &Value) -> Option<Value> {
    let mut parts = key.split('|');
    let name = field(parts.next()?)?;
    let mods: Vec<_> = parts.filter(|m| *m != "all").collect();
    if mods.len() > 1 {
        return None;
    }
    let modifier = mods.first().copied().unwrap_or("");
    let mut value = text(v);
    if value.len() > 200 {
        return None;
    }
    let op = match modifier {
        "" => "eq",
        "contains" => "contains",
        "re" => "regex",
        "cidr" => "cidr",
        "gt" => "gt",
        "lt" => "lt",
        "startswith" => {
            value = format!("^{}", regex::escape(&value));
            "regex"
        }
        "endswith" => {
            value = format!("{}$", regex::escape(&value));
            "regex"
        }
        _ => return None,
    };
    Some(json!({"field":name,"op":op,"value":value}))
}
fn selection(value: &Value) -> Option<Vec<Value>> {
    let map = value.as_object()?;
    let mut conds = Vec::new();
    if map.len() > 64 {
        return None;
    }
    for (key, value) in map {
        if let Some(values) = value.as_array() {
            if values.is_empty() || values.len() > 64 {
                return None;
            }
            if key.split('|').any(|m| m == "all") {
                for v in values {
                    conds.push(clause(key, v)?);
                }
            } else {
                let clauses: Vec<_> = values
                    .iter()
                    .map(|v| clause(key, v))
                    .collect::<Option<_>>()?;
                let first = &clauses[0];
                if !clauses
                    .iter()
                    .all(|c| c["op"] == first["op"] && c["field"] == first["field"])
                {
                    return None;
                }
                let op = first["op"].as_str()?;
                let patterns: Option<Vec<_>> = clauses
                    .iter()
                    .map(|c| {
                        let v = c["value"].as_str()?;
                        Some(match op {
                            "eq" => format!("^{}$", regex::escape(v)),
                            "contains" => regex::escape(v),
                            "regex" => v.to_string(),
                            _ => return None,
                        })
                    })
                    .collect();
                let pattern = format!("(?:{})", patterns?.join("|"));
                if pattern.len() > 200 {
                    return None;
                }
                conds.push(json!({"field":first["field"],"op":"regex","value":pattern}));
            }
        } else {
            conds.push(clause(key, value)?);
        }
    }
    if conds.is_empty() || conds.len() > 64 {
        None
    } else {
        Some(conds)
    }
}
pub fn sigma(input: &str) -> Result<(Vec<Value>, Vec<String>), String> {
    if input.trim().is_empty() || input.len() > 200000 {
        return Err("Empty or oversized Sigma document".into());
    }
    let doc: Value = serde_yaml_ng::from_str(input).map_err(|_| "Invalid Sigma YAML")?;
    let detection = doc["detection"]
        .as_object()
        .ok_or("Sigma detection mapping required")?;
    let condition = detection
        .get("condition")
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim();
    let title = doc["title"].as_str().unwrap_or("Imported Sigma rule");
    let severity = match doc["level"].as_str().unwrap_or("medium") {
        "critical" => "critical",
        "high" | "medium" => "warning",
        _ => "info",
    };
    let mut skipped = Vec::new();
    let names: Vec<String> = if condition == "1 of them" || condition == "all of them" {
        detection
            .keys()
            .filter(|k| *k != "condition" && *k != "timeframe")
            .cloned()
            .collect()
    } else if detection.contains_key(condition) {
        vec![condition.into()]
    } else {
        return Ok((
            vec![],
            vec![format!("Unsupported Sigma condition: {condition}")],
        ));
    };
    let all = condition == "all of them";
    let mut alternatives = Vec::new();
    let mut all_conditions = Vec::new();
    let mut all_invalid = false;
    for name in names.iter().take(64) {
        let value = &detection[name];
        let values = value
            .as_array()
            .cloned()
            .unwrap_or_else(|| vec![value.clone()]);
        if all && values.len() > 1 {
            all_invalid = true;
            skipped.push(format!(
                "{name}: OR-list selection inside all-of cannot be represented"
            ));
            continue;
        }
        for (i, value) in values.iter().take(64).enumerate() {
            match selection(value) {
                Some(conds) => {
                    if all {
                        all_conditions.extend(conds);
                    } else {
                        alternatives.push((format!("{title} / {name} #{}", i + 1), conds));
                    }
                }
                None => {
                    all_invalid = true;
                    skipped.push(format!(
                        "{name}: unmapped field, modifier, or oversized selection"
                    ));
                }
            }
        }
    }
    if all && !all_invalid && !all_conditions.is_empty() {
        alternatives.push((title.into(), all_conditions));
    }
    let rules=alternatives.into_iter().take(64).map(|(name,conds)|json!({"name":name,"conds":conds,"severity":severity,"action":"alert","sigma_id":doc["id"],"enabled":true})).collect();
    Ok((rules, skipped))
}
fn quote(v: &str) -> String {
    serde_json::to_string(v).unwrap()
}
fn yaral_clause(c: &Value) -> Option<String> {
    let field = c["field"].as_str()?;
    let op = c["op"].as_str()?;
    let mut value = text(&c["value"]);
    if field == "protocol" {
        value = value.to_uppercase();
    }
    if field == "direction" {
        value = if value == "out" {
            "OUTBOUND"
        } else {
            "INBOUND"
        }
        .into();
    }
    let lhs = match field {
        "remote_ip" => "$e.target.ip",
        "remote_port" => "$e.target.port",
        "process_name" => "$e.principal.process.file.full_path",
        "protocol" => "$e.network.ip_protocol",
        "direction" => "$e.network.direction",
        "asn" => "$e.network.asn",
        "country" => "$e.target.location.country_or_region",
        "size" => "$e.network.sent_bytes",
        "host" => "$e.network.tls.client.server_name",
        _ => return None,
    };
    let numeric = ["remote_port", "size", "asn"].contains(&field);
    let make = |lhs: &str| -> Option<String> {
        Some(match op {
            "cidr" if field == "remote_ip" => {
                format!("net.ip_in_range_cidr({lhs}, {})", quote(&value))
            }
            "regex" => format!("{lhs} =~ /{}/", value.replace('/', "\\/")),
            "contains" => format!(
                "{lhs} =~ /.*{}.*/",
                regex::escape(&value).replace('/', "\\/")
            ),
            "eq" | "ne" | "gt" | "lt" => {
                let sign = match op {
                    "eq" => "=",
                    "ne" => "!=",
                    "gt" => ">",
                    _ => "<",
                };
                if ["gt", "lt"].contains(&op) && !numeric {
                    return None;
                }
                let rhs = if numeric {
                    value.parse::<f64>().ok()?;
                    value.clone()
                } else {
                    quote(&value)
                };
                format!("{lhs} {sign} {rhs}")
            }
            _ => return None,
        })
    };
    let first = make(lhs)?;
    if field == "host" {
        Some(format!(
            "({first} or {})",
            make("$e.network.dns.questions.name")?
        ))
    } else {
        Some(first)
    }
}
pub fn yaral(rules: &Value) -> String {
    let mut out="// Genyra Snitch: generated YARA-L 2.0 export\n// Packet-sensor fields map to UDM approximations.\n\n".to_string();
    for (index, r) in rules.as_array().into_iter().flatten().enumerate() {
        let id = r["id"]
            .as_str()
            .unwrap_or("rule")
            .chars()
            .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
            .collect::<String>();
        let name = r["name"].as_str().unwrap_or("rule");
        let conds = r["conds"]
            .as_array()
            .cloned()
            .unwrap_or_else(|| vec![r.clone()]);
        let clauses: Option<Vec<_>> = conds.iter().map(yaral_clause).collect();
        let Some(clauses) = clauses.filter(|c| !c.is_empty()) else {
            out.push_str(&format!(
                "// SKIPPED {}: unsupported clause prevents exact translation\n",
                quote(name)
            ));
            continue;
        };
        out.push_str(&format!("rule rust_snitch_{index}_{id} {{\n  meta:\n    description = {}\n    author = \"Genyra Snitch\"\n    severity = {}\n  events:\n    {}\n  condition:\n    $e\n}}\n\n",quote(name),quote(r["severity"].as_str().unwrap_or("info")),clauses.join(" and\n    ")));
    }
    out
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn sigma_and_semantics_and_unmapped_skip() {
        let (r,s)=sigma("title: test\nlevel: high\ndetection:\n  selection:\n    DestinationIp|cidr: 10.0.0.0/8\n    DestinationPort: 4444\n  condition: selection\n").unwrap();
        assert!(s.is_empty());
        assert_eq!(r[0]["conds"].as_array().unwrap().len(), 2);
        assert_eq!(r[0]["severity"], "warning");
        let (r, s) =
            sigma("detection:\n  x:\n    UnmappedField: anything\n  condition: x\n").unwrap();
        assert!(r.is_empty());
        assert_eq!(s.len(), 1);
    }
    #[test]
    fn all_of_never_widens_invalid_selection() {
        let (r,s)=sigma("detection:\n  a:\n    DestinationPort: 443\n  b:\n    CommandLine: surprise\n  condition: all of them\n").unwrap();
        assert!(r.is_empty());
        assert!(!s.is_empty());
    }
    #[test]
    fn yaral_preserves_all_and_clauses() {
        let y = yaral(
            &json!([{"id":"a-b","name":"test","severity":"warning","conds":[{"field":"remote_port","op":"eq","value":"443"},{"field":"host","op":"contains","value":"example.com"}]}]),
        );
        assert!(y.contains("$e.target.port = 443 and"));
        assert!(y.contains("network.dns.questions.name"));
    }
}
