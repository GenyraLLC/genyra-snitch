//! Exercise the actual collector's persistent identity, exclusive ownership,
//! graceful shutdown and restart. No host traffic or system service is touched.
use serde_json::{json, Value};
use std::{
    process::{Child, Command, Stdio},
    time::Duration,
};
struct Owned(Child);
impl Drop for Owned {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
fn start(data: &std::path::Path) -> Owned {
    Owned(
        Command::new(env!("CARGO_BIN_EXE_genyra-snitch"))
            .args(["--demo", "--bind", "127.0.0.1", "--port", "0", "--data-dir"])
            .arg(data)
            .env_remove("SNITCH_TOKEN")
            .env_remove("SNITCH_DATA_DIR")
            .env_remove("SNITCH_BIND")
            .env_remove("SNITCH_PORT")
            .env_remove("SNITCH_TLS_CERT")
            .env_remove("SNITCH_TLS_KEY")
            .env_remove("SNITCH_REPLAY_PCAP")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    )
}
async fn ready(
    collector: &mut Owned,
    data: &std::path::Path,
    client: &reqwest::Client,
) -> (String, String) {
    for _ in 0..150 {
        assert!(
            collector.0.try_wait().unwrap().is_none(),
            "collector exited before readiness"
        );
        if let (Ok(endpoint), Ok(token)) =
            (genyra_common::endpoint(data), genyra_common::token(data))
        {
            if client
                .get(format!("{}/diagnostics", endpoint.url))
                .header("X-Snitch-Token", &token)
                .send()
                .await
                .is_ok_and(|r| r.status().is_success())
            {
                assert_eq!(endpoint.pid, collector.0.id());
                return (endpoint.url, token);
            }
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("collector did not become ready");
}
async fn stop(collector: &mut Owned, client: &reqwest::Client, base: &str, token: &str) {
    client
        .post(format!("{base}/shutdown"))
        .header("X-Snitch-Token", token)
        .json(&json!({}))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap();
    for _ in 0..200 {
        if let Some(status) = collector.0.try_wait().unwrap() {
            assert!(status.success());
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("collector did not complete graceful shutdown");
}
#[tokio::test]
async fn one_collector_persists_identity_and_history_across_restart() {
    let dir = tempfile::tempdir().unwrap();
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(3))
        .no_proxy()
        .build()
        .unwrap();
    let mut first = start(dir.path());
    let (base, token) = ready(&mut first, dir.path(), &client).await;
    client
        .post(format!("{base}/settings"))
        .header("X-Snitch-Token", &token)
        .json(&json!({"settings":{"retention_hours":73}}))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap();
    let mut duplicate = start(dir.path());
    let mut rejected = false;
    for _ in 0..100 {
        if let Some(status) = duplicate.0.try_wait().unwrap() {
            assert!(!status.success());
            rejected = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert!(rejected, "second collector was not rejected");
    assert_eq!(
        genyra_common::endpoint(dir.path()).unwrap().pid,
        first.0.id()
    );
    assert_eq!(genyra_common::token(dir.path()).unwrap(), token);
    stop(&mut first, &client, &base, &token).await;
    assert!(
        genyra_common::endpoint(dir.path()).is_err(),
        "stopped collector left live discovery metadata"
    );
    let mut second = start(dir.path());
    let (base2, token2) = ready(&mut second, dir.path(), &client).await;
    assert_eq!(token, token2);
    let settings: Value = client
        .get(format!("{base2}/settings"))
        .header("X-Snitch-Token", &token)
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(settings["settings"]["retention_hours"], 73);
    stop(&mut second, &client, &base2, &token).await;
    assert!(genyra_common::Instance::acquire(dir.path()).is_ok());
}
