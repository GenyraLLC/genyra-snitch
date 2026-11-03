//! eBPF and cgroups are Linux facilities, not portable firewall APIs.
use crate::{process::Owner, App};
use serde_json::{json, Value};
use std::{collections::HashSet, net::IpAddr};
#[derive(Default)]
pub struct Kernel;
impl Kernel {
    pub fn sync_process_policy(&self, _: &HashSet<String>) -> Result<(), String> {
        Ok(())
    }
    pub fn probe_status(&self) -> Value {
        json!({"available":false,"running":false,"events":0,"recent":[],"reason":"eBPF connect tracing requires Linux"})
    }
    pub fn enforcer_status(&self) -> Value {
        json!({"available":false,"active":false,"reason":"cgroup eBPF enforcement requires Linux; use the platform firewall"})
    }
    pub fn owner(&self, _: IpAddr, _: u16) -> Option<Owner> {
        None
    }
    pub fn block(&self, _: IpAddr) -> Result<(), String> {
        Err("eBPF requires Linux; use a firewall rule".into())
    }
    pub fn isolate(&self, _: u32) -> Result<(), String> {
        Err("cgroup isolation requires Linux".into())
    }
}
pub fn run(_: App) {}
