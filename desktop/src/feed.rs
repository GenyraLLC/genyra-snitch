//! One bounded live-event receiver. It disconnects when the window is paused
//! or minimized; reconnect always starts from the collector's full snapshot.
use super::Connection;
use eframe::egui;
use futures_util::{SinkExt, StreamExt};
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, VecDeque},
    sync::mpsc,
    time::Duration,
};
use tokio_tungstenite::tungstenite::{
    client::IntoClientRequest,
    protocol::{Message, WebSocketConfig},
};
pub(super) struct Feed {
    mode: tokio::sync::watch::Sender<bool>,
    pub(super) messages: mpsc::Receiver<Value>,
}
impl Feed {
    pub(super) fn new(connection: Connection, ctx: egui::Context) -> Self {
        let (mode, mut active) = tokio::sync::watch::channel(false);
        let (send, messages) = mpsc::sync_channel(1);
        std::thread::Builder::new().name("traffic-events".into()).spawn(move||{
            let runtime=tokio::runtime::Builder::new_current_thread().enable_all().build().expect("traffic event runtime");
            runtime.block_on(async move {
                let url=format!("{}/ws",connection.base.replacen("http://","ws://",1));
                loop {
                    if !*active.borrow(){if active.changed().await.is_err(){break;}continue;}
                    let mut request=match url.as_str().into_client_request(){Ok(request)=>request,Err(_)=>break};
                    let Ok(token)=connection.token.parse()else{break;};request.headers_mut().insert("X-Snitch-Token",token);
                    let config=WebSocketConfig::default().max_message_size(Some(16*1024*1024)).max_frame_size(Some(16*1024*1024));
                    let attempt=tokio::select! {result=tokio::time::timeout(Duration::from_secs(3),tokio_tungstenite::connect_async_with_config(request,Some(config),false))=>result,_=active.changed()=>continue};
                    match attempt {
                        Ok(Ok((mut socket,_)))=>{
                            loop {
                                tokio::select! {
                                    changed=active.changed()=>{
                                        if changed.is_err()||!*active.borrow(){let _=tokio::time::timeout(Duration::from_secs(1),socket.close(None)).await;break;}
                                    }
                                    message=socket.next()=>{
                                        match message {
                                            Some(Ok(Message::Text(text)))=>{
                                                let Ok(value)=serde_json::from_str::<Value>(&text)else{continue;};
                                                if empty_batch(&value){continue;}
                                                if send.send(value).is_err(){return;}ctx.request_repaint();
                                            }
                                            Some(Ok(Message::Ping(payload)))=>{if socket.send(Message::Pong(payload)).await.is_err(){break;}}
                                            Some(Ok(Message::Close(_)))|Some(Err(_))|None=>{
                                                if send.send(json!({"type":"feed_error","error":"Traffic feed disconnected"})).is_err(){return;}
                                                ctx.request_repaint();break;
                                            },
                                            _=>{}
                                        }
                                    }
                                }
                            }
                        }
                        other=>{
                            let error=match other{Ok(Err(error))=>error.to_string(),_=>"Traffic feed connection timed out".into()};
                            if send.send(json!({"type":"feed_error","error":error})).is_err(){break;}ctx.request_repaint();
                        }
                    }
                    tokio::select! {_=tokio::time::sleep(Duration::from_secs(1))=>{},changed=active.changed()=>{if changed.is_err(){break;}}}
                }
            });
        }).expect("traffic event receiver");
        Self { mode, messages }
    }
    pub(super) fn set_active(&self, enabled: bool) {
        self.mode.send_if_modified(|current| {
            if *current == enabled {
                false
            } else {
                *current = enabled;
                true
            }
        });
    }
}
impl Drop for Feed {
    fn drop(&mut self) {
        let _ = self.mode.send(false);
    }
}
fn empty_batch(value: &Value) -> bool {
    value["type"] == "batch"
        && ["nodes", "devices", "edges", "packets", "alerts", "removed"]
            .iter()
            .all(|key| value[*key].as_array().is_none_or(Vec::is_empty))
}

#[derive(Default)]
pub(super) struct State {
    nodes: BTreeMap<String, Value>,
    edges: BTreeMap<String, Value>,
    pub(super) packets: VecDeque<Value>,
    pub(super) alerts: VecDeque<Value>,
}
impl State {
    pub(super) fn apply(&mut self, value: &Value) -> bool {
        let kind = value["type"].as_str().unwrap_or("");
        if !["init", "reset", "batch", "nodes_removed"].contains(&kind) {
            return false;
        }
        if kind == "init" || kind == "reset" {
            self.nodes.clear();
            self.edges.clear();
            self.packets.clear();
            self.alerts.clear();
        }
        for key in ["nodes", "devices"] {
            for node in value[key].as_array().into_iter().flatten() {
                if let Some(id) = node["id"].as_str() {
                    if self.nodes.len() < 4097 || self.nodes.contains_key(id) {
                        self.nodes.insert(id.into(), node.clone());
                    }
                }
            }
        }
        for edge in value["edges"].as_array().into_iter().flatten() {
            if let Some(id) = edge["id"].as_str() {
                if self.edges.len() < 65536 || self.edges.contains_key(id) {
                    self.edges.insert(id.into(), edge.clone());
                }
            }
        }
        for key in ["ids", "removed"] {
            for id in value[key]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
            {
                self.nodes.remove(id);
            }
        }
        self.edges.retain(|_, edge| {
            edge["target"]
                .as_str()
                .is_some_and(|target| self.nodes.contains_key(target))
        });
        for packet in value["packets"].as_array().into_iter().flatten() {
            if self.packets.len() >= 128 {
                self.packets.pop_front();
            }
            self.packets.push_back(packet.clone());
        }
        for alert in value["alerts"].as_array().into_iter().flatten() {
            if self.alerts.len() >= 100 {
                self.alerts.pop_back();
            }
            self.alerts.push_front(alert.clone());
        }
        true
    }
    pub(super) fn graph(&self) -> Value {
        json!({"nodes":self.nodes.values().collect::<Vec<_>>(),"edges":self.edges.values().collect::<Vec<_>>()})
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn removal_and_reset_do_not_leave_stale_nodes_or_edges() {
        let mut state = State::default();
        state.apply(&json!({"type":"init","nodes":[{"id":"local"},{"id":"a","bytes":5}],"edges":[{"id":"edge","source":"local","target":"a"}]}));
        state.apply(&json!({"type":"batch","nodes":[{"id":"a","bytes":9}]}));
        assert_eq!(state.graph()["nodes"][0]["bytes"], 9);
        state.apply(&json!({"type":"nodes_removed","ids":["a"]}));
        assert_eq!(state.graph()["edges"].as_array().unwrap().len(), 0);
        state.apply(&json!({"type":"reset","nodes":[{"id":"b"}]}));
        assert_eq!(state.graph()["nodes"].as_array().unwrap().len(), 1);
        assert_eq!(state.graph()["nodes"][0]["id"], "b");
    }
    #[test]
    fn packet_history_is_bounded_without_losing_latest_samples() {
        let mut state = State::default();
        for i in 0..1000 {
            state.apply(&json!({"type":"batch","packets":[{"sample":i}]}));
        }
        assert_eq!(state.packets.len(), 128);
        assert_eq!(state.packets.back().unwrap()["sample"], 999);
    }
}
