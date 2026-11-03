use crate::{integrity, App};
use serde_json::{json, Value};
use std::{
    collections::{BTreeSet, HashMap},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
struct Handler {
    events: Arc<Mutex<Vec<Value>>>,
    errors: Arc<Mutex<Vec<String>>>,
}
impl frida::ScriptHandler for Handler {
    fn on_message(&mut self, message: frida::Message, _data: Option<Vec<u8>>) {
        match message {
            frida::Message::Send(message) => {
                if let Ok(mut events) = self.events.lock() {
                    if events.len() < 1000 && message.payload.returns.is_object() {
                        events.push(message.payload.returns);
                    }
                }
            }
            frida::Message::Error(error) => {
                if let Ok(mut errors) = self.errors.lock() {
                    if errors.len() < 10 {
                        errors.push(format!("{error:?}").chars().take(1000).collect());
                    }
                }
            }
            _ => {}
        }
    }
}
pub fn inspect(a: &App, pid: u32, seconds: u64) -> Value {
    let Ok(_guard) = a.deep_busy.try_lock() else {
        return json!({"ok":false,"error":"another inspection is running","events":[],"flows":[],"modules":{}});
    };
    let seconds = seconds.clamp(3, 60);
    let events = Arc::new(Mutex::new(Vec::new()));
    let errors = Arc::new(Mutex::new(Vec::new()));
    let result = (|| -> Result<(), String> {
        // The handle, manager, session and script stay on this inspection
        // thread; only the bounded callback buffers are shared.
        static FRIDA: std::sync::OnceLock<frida::Frida> = std::sync::OnceLock::new();
        let frida = FRIDA.get_or_init(|| unsafe { frida::Frida::obtain() });
        let manager = frida::DeviceManager::obtain(frida);
        let device = manager
            .get_device_by_type(frida::DeviceType::Local)
            .map_err(|e| format!("Device lookup failed: {e:?}"))?;
        let session = device
            .attach(pid)
            .map_err(|e| format!("Attach failed (permissions or target exited): {e:?}"))?;
        let mut options = frida::ScriptOption::new();
        let mut script = session
            .create_script(
                include_str!("../resources/deep-inspection.js"),
                &mut options,
            )
            .map_err(|e| format!("Script creation failed: {e:?}"))?;
        script
            .handle_message(Handler {
                events: events.clone(),
                errors: errors.clone(),
            })
            .map_err(|e| format!("Script handler failed: {e:?}"))?;
        script
            .load()
            .map_err(|e| format!("Script load failed: {e:?}"))?;
        let deadline = Instant::now() + Duration::from_secs(seconds);
        while Instant::now() < deadline
            && !a.stop.load(std::sync::atomic::Ordering::Relaxed)
            && !session.is_detached()
        {
            std::thread::sleep(Duration::from_millis(100));
        }
        let _ = script.unload();
        let _ = session.detach();
        Ok(())
    })();
    if let Err(error) = result {
        return json!({"ok":false,"error":error,"events":[],"flows":[],"modules":{}});
    }
    let captured = events.lock().unwrap().clone();
    let mut connections = Vec::new();
    let mut flows = Vec::new();
    let mut modules = HashMap::<String, u64>::new();
    let mut suspicious = BTreeSet::new();
    for mut event in captured {
        *modules
            .entry(event["module"].as_str().unwrap_or("?").into())
            .or_default() += 1;
        if let Some(path) = event["path"].as_str() {
            let lower = path.to_lowercase();
            if [
                "/tmp/",
                "/var/tmp/",
                "/dev/shm/",
                "memfd:",
                "/downloads/",
                "/.cache/",
            ]
            .iter()
            .any(|p| lower.contains(p))
            {
                suspicious.insert(path.to_string());
            }
        }
        if event["kind"] == "send" {
            let hex = event["head"].as_str().unwrap_or("");
            let bytes: Vec<_> = (0..hex.len().min(32))
                .step_by(2)
                .filter_map(|i| {
                    hex.get(i..i + 2)
                        .and_then(|s| u8::from_str_radix(s, 16).ok())
                })
                .collect();
            if let Some(object) = event.as_object_mut() {
                object.remove("head");
            }
            event["sha256_head"] = json!(integrity::sha(bytes));
            if flows.len() < 500 {
                flows.push(event);
            }
        } else if event["ip"].is_string() && connections.len() < 500 {
            connections.push(event);
        }
    }
    if !suspicious.is_empty() {
        a.engine.lock().unwrap().alert(
            "INJECT_SUSPECT",
            "",
            "critical",
            format!("Injected-module suspicion in pid {pid}"),
            json!({"pid":pid,"paths":suspicious}),
        );
    }
    let errors = errors.lock().unwrap().clone();
    json!({"ok":errors.is_empty(),"pid":pid,"seconds":seconds,"events":connections,"flows":flows,"modules":modules,"suspicious_paths":suspicious,"errors":errors,"implementation":"frida-core native"})
}
