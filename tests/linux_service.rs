//! Explicit opt-in check of the native user-service installer. Never touches
//! an existing service or captures host traffic; the registration is removed.
#![cfg(target_os = "linux")]
use serde_json::{json, Value};
use std::{path::PathBuf, process::Command, time::Duration};
struct Registration {
    binary: PathBuf,
    data: PathBuf,
}
impl Drop for Registration {
    fn drop(&mut self) {
        let _ = genyra_common::service::manage(&self.binary, &self.data, "uninstall");
    }
}
#[tokio::test]
#[ignore = "Explicitly installs and removes a temporary systemd user service; requires an active user session"]
async fn native_user_service_installs_starts_restarts_and_uninstalls() {
    let binary = PathBuf::from(env!("CARGO_BIN_EXE_genyra-snitch"));
    let temporary = tempfile::tempdir().unwrap();
    let data = temporary.path().join("data");
    let status = genyra_common::service::manage(&binary, &data, "status").unwrap();
    assert!(
        status.contains("LoadState=not-found"),
        "refusing to touch an existing Genyra service"
    );
    genyra_common::service::manage(&binary, &data, "install").unwrap();
    let registration = Registration {
        binary: binary.clone(),
        data: data.clone(),
    };
    let base = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(std::env::var_os("HOME").unwrap()).join(".config"));
    let path = base.join("systemd/user/genyra-snitch.service");
    let unit = std::fs::read_to_string(&path).unwrap();
    // Only the owned test registration receives a demo argument. The real
    // installer always produces live-monitoring configuration.
    std::fs::write(&path, unit.replace("--no-browser", "--no-browser --demo")).unwrap();
    assert!(Command::new("systemctl")
        .args(["--user", "daemon-reload"])
        .status()
        .unwrap()
        .success());
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(2))
        .no_proxy()
        .build()
        .unwrap();
    let mut original_token = None;
    for round in 0..2 {
        genyra_common::service::manage(&binary, &data, "start").unwrap();
        let mut connected = None;
        for _ in 0..200 {
            if let (Ok(endpoint), Ok(token)) =
                (genyra_common::endpoint(&data), genyra_common::token(&data))
            {
                if let Ok(response) = client
                    .get(format!("{}/diagnostics", endpoint.url))
                    .header("X-Snitch-Token", &token)
                    .send()
                    .await
                {
                    if response.status().is_success() {
                        connected =
                            Some((endpoint, token, response.json::<Value>().await.unwrap()));
                        break;
                    }
                }
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        let (endpoint, token, diagnostics) =
            connected.expect("systemd collector did not become ready");
        assert_eq!(diagnostics["product"], "Genyra Snitch");
        assert_eq!(diagnostics["capture"]["demo"], true);
        assert!(genyra_common::Instance::acquire(&data).is_err());
        if round == 0 {
            original_token = Some(token.clone());
            client
                .post(format!("{}/settings", endpoint.url))
                .header("X-Snitch-Token", &token)
                .json(&json!({"settings":{"retention_hours":73}}))
                .send()
                .await
                .unwrap()
                .error_for_status()
                .unwrap();
        } else {
            assert_eq!(original_token.as_ref(), Some(&token));
            let settings: Value = client
                .get(format!("{}/settings", endpoint.url))
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
        }
        genyra_common::service::manage(&binary, &data, "stop").unwrap();
        assert!(genyra_common::endpoint(&data).is_err());
        assert!(genyra_common::Instance::acquire(&data).is_ok());
    }
    drop(registration);
    assert!(!path.exists());
    let status = genyra_common::service::manage(&binary, &data, "status").unwrap();
    assert!(status.contains("LoadState=not-found"));
}
