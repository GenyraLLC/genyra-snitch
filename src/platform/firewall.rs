//! OS firewall adapters. Commands receive structured data, never interpolated
//! user text in a shell. Each adapter owns only its named rule group/anchor.
use serde_json::{json, Value};
use std::{
    io::Write,
    net::ToSocketAddrs,
    process::{Command, Stdio},
};

fn targets(rule: &Value) -> Result<Vec<String>, String> {
    let value = rule["value"].as_str().ok_or("Missing firewall target")?;
    match rule["kind"].as_str().unwrap_or("") {
        "ip" | "cidr" => Ok(vec![value
            .parse::<ipnet::IpNet>()
            .or_else(|_| value.parse::<std::net::IpAddr>().map(ipnet::IpNet::from))
            .map_err(|e| e.to_string())?
            .to_string()]),
        "domain" => {
            let targets: std::collections::BTreeSet<_> = (value, 0)
                .to_socket_addrs()
                .map_err(|e| e.to_string())?
                .take(32)
                .map(|s| s.ip().to_string())
                .collect();
            if targets.is_empty() {
                return Err("Domain resolved to no addresses".into());
            }
            Ok(targets.into_iter().collect())
        }
        _ => Ok(vec![]),
    }
}

pub fn supported() -> bool {
    #[cfg(windows)]
    {
        true
    }
    #[cfg(target_os = "macos")]
    {
        std::path::Path::new("/sbin/pfctl").is_file()
    }
}

pub fn sync(settings: &Value) -> Result<(), String> {
    // Policy worker retries, but unchanged successful policy does no OS work.
    static APPLIED: std::sync::OnceLock<std::sync::Mutex<Option<String>>> =
        std::sync::OnceLock::new();
    let mut applied = APPLIED.get_or_init(Default::default).lock().unwrap();
    let signature = json!([settings["firewall_rules"], settings["firewall_lockdown"]]).to_string();
    if applied.as_deref() == Some(&signature) {
        return Ok(());
    }
    let rules = settings["firewall_rules"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    let mut compiled = vec![];
    for rule in rules.iter().filter(|r| r["enabled"] != false) {
        if rule["action"].as_str().unwrap_or("block") != "block" {
            return Err("This platform adapter currently supports block rules; sinkhole/throttle are not ported".into());
        }
        let value = rule["value"].as_str().ok_or("Missing firewall target")?;
        compiled.push(
            json!({"id":rule["id"],"kind":rule["kind"],"value":value,"targets":targets(rule)?}),
        );
    }
    apply(&compiled, settings["firewall_lockdown"] == true)?;
    *applied = Some(signature);
    Ok(())
}

#[cfg(windows)]
fn apply(rules: &[Value], lockdown: bool) -> Result<(), String> {
    let mut specifications = vec![];
    for rule in rules {
        match rule["kind"].as_str().unwrap_or("") {
            "ip" | "cidr" | "domain" => specifications.push(json!({"addresses":rule["targets"]})),
            "port" => {
                let port = rule["value"]
                    .as_str()
                    .and_then(|s| s.parse::<u16>().ok())
                    .filter(|p| *p != 0)
                    .ok_or("Invalid port")?;
                for protocol in ["TCP", "UDP"] {
                    specifications.push(json!({"port":port,"protocol":protocol}));
                }
            }
            "process" => {
                let value = rule["value"].as_str().unwrap_or("");
                let path = if std::path::Path::new(value).is_absolute() {
                    std::path::PathBuf::from(value)
                } else {
                    let system = sysinfo::System::new_all();
                    system
                        .processes()
                        .values()
                        .find(|p| p.name().to_string_lossy().eq_ignore_ascii_case(value))
                        .and_then(|p| p.exe())
                        .map(std::path::Path::to_path_buf)
                        .ok_or("Process executable cannot be resolved")?
                };
                if !path.is_file() {
                    return Err("Process executable does not exist".into());
                }
                specifications.push(json!({"program":path}));
            }
            _ => return Err("Unknown firewall rule kind".into()),
        }
    }
    if lockdown {
        specifications.push(json!({"lockdown":true}));
    }
    // Create the next generation completely before removing previous rules.
    // On failure the previous generation remains and only new rules roll back.
    let script = r#"$ErrorActionPreference='Stop'
$spec=[Console]::In.ReadToEnd() | ConvertFrom-Json
$group='Genyra Snitch'
$old=@(Get-NetFirewallRule -Group $group -ErrorAction SilentlyContinue)
$created=@()
try {
 foreach($r in $spec.rules) {
  $params=@{DisplayName=('Genyra Snitch '+[guid]::NewGuid().ToString());Group=$group;Direction='Outbound';Action='Block';Enabled='True';Profile='Any'}
  if($r.addresses){$params.RemoteAddress=@($r.addresses)}
  if($r.program){$params.Program=$r.program}
  if($r.port){$params.RemotePort=$r.port;$params.Protocol=$r.protocol}
  if($r.lockdown){$params.RemoteAddress=@('0.0.0.0/1','128.0.0.0/1','::/1','8000::/1')}
  $created+=New-NetFirewallRule @params
 }
 $old | Remove-NetFirewallRule
} catch {
 $created | Remove-NetFirewallRule -ErrorAction SilentlyContinue
 [Console]::Error.WriteLine($_.Exception.Message);exit 1
}
"#;
    let mut child = Command::new("powershell.exe")
        .args(["-NoProfile", "-NonInteractive", "-Command", script])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| e.to_string())?;
    child
        .stdin
        .take()
        .unwrap()
        .write_all(json!({"rules":specifications}).to_string().as_bytes())
        .map_err(|e| e.to_string())?;
    let output = child.wait_with_output().map_err(|e| e.to_string())?;
    if output.status.success() {
        Ok(())
    } else {
        Err(String::from_utf8_lossy(&output.stderr)
            .chars()
            .take(2000)
            .collect())
    }
}

#[cfg(target_os = "macos")]
fn apply(rules: &[Value], lockdown: bool) -> Result<(), String> {
    let root = Command::new("/sbin/pfctl")
        .arg("-sr")
        .output()
        .map_err(|e| e.to_string())?;
    if !root.status.success() {
        return Err(String::from_utf8_lossy(&root.stderr).into_owned());
    }
    if !String::from_utf8_lossy(&root.stdout).contains("anchor \"com.apple/*\"") {
        return Err("PF root rules do not reference com.apple/*; refusing to load an unreferenced anchor or alter host policy".into());
    }
    let status = Command::new("/sbin/pfctl")
        .args(["-s", "info"])
        .output()
        .map_err(|e| e.to_string())?;
    if !String::from_utf8_lossy(&status.stdout).contains("Status: Enabled") {
        return Err("PF is disabled; enable the packet filter before applying Genyra rules".into());
    }
    let mut text = String::new();
    for rule in rules {
        match rule["kind"].as_str().unwrap_or("") {
            "ip" | "cidr" | "domain" => {
                for target in rule["targets"].as_array().unwrap() {
                    let ip = target.as_str().unwrap();
                    text.push_str(&format!(
                        "block drop out quick {} to {ip}\n",
                        if ip.contains(':') { "inet6" } else { "inet" }
                    ));
                }
            }
            "port" => {
                let port = rule["value"]
                    .as_str()
                    .and_then(|s| s.parse::<u16>().ok())
                    .filter(|p| *p != 0)
                    .ok_or("Invalid port")?;
                text.push_str(&format!(
                    "block drop out quick proto {{ tcp, udp }} to any port {port}\n"
                ));
            }
            "process" => return Err(
                "PF does not support per-process rules; a Network Extension provider is required"
                    .into(),
            ),
            _ => return Err("Unknown firewall rule kind".into()),
        }
    }
    if lockdown {
        text.push_str("pass out quick on lo0 all\npass out quick to { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, fc00::/7, fe80::/10 }\nblock drop out all\n");
    }
    let mut child = Command::new("/sbin/pfctl")
        .args(["-a", "com.apple/genyra-snitch", "-f", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| e.to_string())?;
    child
        .stdin
        .take()
        .unwrap()
        .write_all(text.as_bytes())
        .map_err(|e| e.to_string())?;
    let output = child.wait_with_output().map_err(|e| e.to_string())?;
    if output.status.success() {
        Ok(())
    } else {
        Err(String::from_utf8_lossy(&output.stderr).into_owned())
    }
}
