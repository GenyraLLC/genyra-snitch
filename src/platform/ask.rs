//! NFQUEUE is a Linux facility. A native WFP/Network Extension decision
//! provider must be implemented and tested before this can be advertised.
use crate::App;
use serde_json::{json, Value};
use std::net::IpAddr;
#[derive(Default)]
pub struct Ask;
impl Ask {
    pub fn status(&self, _: &Value) -> Value {
        json!({"available":false,"running":false,"pending":0,"reason":"Interactive first-flow provider has not been ported to this OS"})
    }
    pub fn decide(&self, _: IpAddr, _: u16, _: &str, _: bool) -> bool {
        false
    }
}
pub fn run(_: App) {}
