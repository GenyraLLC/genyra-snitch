//! Local-only model explanations. Embedded mode uses a native llama.cpp
//! completion executable; neither mode invokes a Python interpreter.
use crate::{integrity, App};
use serde_json::{json, Value};
use std::{
    collections::HashMap,
    path::PathBuf,
    process::Stdio,
    sync::Mutex,
    time::{Duration, Instant},
};
#[derive(Default)]
pub struct Slm {
    cache: Mutex<HashMap<String, (Instant, String)>>,
}
fn endpoint(settings: &Value) -> Option<reqwest::Url> {
    let url = reqwest::Url::parse(
        settings["slm_endpoint"]
            .as_str()
            .filter(|s| !s.is_empty())
            .unwrap_or("http://127.0.0.1:11434"),
    )
    .ok()?;
    let host = url.host_str()?.trim_matches(['[', ']']);
    if !["http", "https"].contains(&url.scheme())
        || !(host == "localhost"
            || host
                .parse::<std::net::IpAddr>()
                .is_ok_and(|ip| ip.is_loopback()))
    {
        return None;
    }
    Some(url)
}
fn native_binary() -> Option<PathBuf> {
    if let Some(path) = std::env::var_os("SNITCH_LLAMA_CLI").map(PathBuf::from) {
        return path.is_file().then_some(path);
    }
    for name in ["llama-completion", "llama-cli"] {
        if let Some(path) = std::env::var_os("PATH").and_then(|p| {
            std::env::split_paths(&p)
                .map(|p| p.join(name))
                .find(|p| p.is_file())
        }) {
            return Some(path);
        }
    }
    None
}
fn client() -> reqwest::Client {
    reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(12))
        .build()
        .unwrap()
}
async fn response(mut r: reqwest::Response) -> Result<Value, String> {
    if !r.status().is_success() {
        return Err(format!("HTTP {}", r.status().as_u16()));
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = r.chunk().await.map_err(|_| "Response read failed")? {
        if bytes.len() + chunk.len() > 1024 * 1024 {
            return Err("Response exceeds 1 MiB".into());
        }
        bytes.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&bytes).map_err(|_| "Invalid model-server JSON".into())
}
async fn models(http: &reqwest::Client, url: &reqwest::Url) -> Option<Value> {
    let base = url.as_str().trim_end_matches('/');
    let reply = http.get(format!("{base}/api/tags")).send().await.ok()?;
    response(reply).await.ok()
}
pub async fn status(a: &App) -> Value {
    let settings = a.engine.lock().unwrap().settings.clone();
    let enabled = settings["slm_enabled"] == true;
    let mode = settings["slm_mode"]
        .as_str()
        .filter(|s| !s.is_empty())
        .unwrap_or("ollama");
    if mode == "embedded" {
        let path = settings["slm_model_path"].as_str().unwrap_or("");
        let runtime = native_binary();
        let exists = std::path::Path::new(path).is_file();
        return json!({"enabled":enabled,"reachable":enabled&&exists&&runtime.is_some(),"mode":"embedded","model_path":path,"model":settings["slm_model"].as_str().unwrap_or(""),"loopback_only":true,"runtime":"native llama.cpp completion","error":if runtime.is_none(){Some("native llama-completion/llama-cli not found; set SNITCH_LLAMA_CLI")}else if !exists{Some("GGUF model file not found")}else{None}});
    }
    let url = endpoint(&settings);
    let detected = if enabled {
        if let Some(url) = &url {
            models(&client(), url).await
        } else {
            None
        }
    } else {
        None
    };
    json!({"enabled":enabled,"reachable":detected.is_some(),"mode":"ollama","endpoint":url.map(|u|u.to_string()).unwrap_or_default(),"model":settings["slm_model"].as_str().filter(|s|!s.is_empty()).map(str::to_string).or_else(||detected.as_ref().and_then(|v|v["models"].as_array()?.first()?["name"].as_str().map(str::to_string))).unwrap_or_default(),"loopback_only":true})
}
pub async fn enrich(a: &App, kind: &str, details: &Value, lang: &str) -> Option<String> {
    let settings = a.engine.lock().unwrap().settings.clone();
    if settings["slm_enabled"] != true {
        return None;
    }
    let key=format!("{kind}:{lang}:{}:{}",integrity::sha(json!({"mode":settings["slm_mode"],"model":settings["slm_model"],"path":settings["slm_model_path"],"endpoint":settings["slm_endpoint"]}).to_string()),integrity::sha(details.to_string()));
    let cached = {
        a.slm
            .cache
            .lock()
            .unwrap()
            .get(&key)
            .filter(|(at, _)| at.elapsed() < Duration::from_secs(300))
            .map(|(_, text)| text.clone())
    };
    if cached.is_some() {
        return cached;
    }
    let detail = details.to_string().chars().take(600).collect::<String>();
    let prompt=format!("You are a security assistant inside a local-only network monitor. Explain this alert in {} in at most four short sentences: what it means, why it fired, and what the user should check. No preamble.\nALERT TYPE: {kind}\nDETAILS: {detail}",if lang=="fr"{"French"}else{"English"});
    let text = if settings["slm_mode"] == "embedded" {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let path = settings["slm_model_path"].as_str()?;
        if !std::path::Path::new(path).is_file() {
            return None;
        }
        let binary = native_binary()?;
        let tokens = std::env::var("SNITCH_SLM_MAX_TOKENS")
            .ok()
            .and_then(|s| s.parse::<u32>().ok())
            .unwrap_or(160)
            .clamp(1, 160)
            .to_string();
        let mut child = tokio::process::Command::new(binary)
            .args([
                "-m",
                path,
                "-ngl",
                "0",
                "-t",
                "2",
                "-tb",
                "2",
                "-c",
                "512",
                "-n",
                &tokens,
                "--temp",
                "0.3",
                "--no-display-prompt",
                "--simple-io",
                "--no-conversation",
                "-co",
                "off",
                "-f",
                "/dev/stdin",
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .ok()?;
        let mut input = child.stdin.take()?;
        input.write_all(prompt.as_bytes()).await.ok()?;
        drop(input);
        let output = child.stdout.take()?;
        let read = async {
            let mut bytes = Vec::new();
            output.take(65536).read_to_end(&mut bytes).await.ok()?;
            if !child.wait().await.ok()?.success() {
                return None;
            }
            Some(String::from_utf8_lossy(&bytes).into_owned())
        };
        tokio::time::timeout(Duration::from_secs(120), read)
            .await
            .ok()??
    } else {
        let url = endpoint(&settings)?;
        let http = client();
        let model = if let Some(model) = settings["slm_model"].as_str().filter(|s| !s.is_empty()) {
            model.to_string()
        } else {
            let models = models(&http, &url).await?;
            models["models"].as_array()?.first()?["name"]
                .as_str()?
                .to_string()
        };
        let reply=http.post(format!("{}/api/generate",url.as_str().trim_end_matches('/'))).json(&json!({"model":model,"prompt":prompt,"stream":false,"options":{"num_predict":160,"temperature":0.3}})).send().await.ok()?;
        response(reply).await.ok()?["response"]
            .as_str()?
            .to_string()
    };
    let text = text.trim().chars().take(4000).collect::<String>();
    if text.is_empty() {
        return None;
    }
    let mut cache = a.slm.cache.lock().unwrap();
    if cache.len() >= 128 {
        cache.retain(|_, (at, _)| at.elapsed() < Duration::from_secs(300));
        if cache.len() >= 128 {
            if let Some(old) = cache.keys().next().cloned() {
                cache.remove(&old);
            }
        }
    }
    cache.insert(key, (Instant::now(), text.clone()));
    Some(text)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn model_endpoints_are_strictly_loopback() {
        assert!(endpoint(&json!({"slm_endpoint":"http://127.0.0.1:1234"})).is_some());
        assert!(endpoint(&json!({"slm_endpoint":"https://example.com"})).is_none());
        assert!(endpoint(&json!({"slm_endpoint":"file:///etc/passwd"})).is_none());
    }
}
