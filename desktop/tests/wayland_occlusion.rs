//! Opt-in compositor regression: an owned off-screen window must still answer
//! Wayland close requests. NVIDIA EGL previously blocked in SwapBuffers.
#![cfg(target_os = "linux")]
use serde_json::{json, Value};
use std::{
    path::PathBuf,
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};
struct OwnedWindow {
    child: Child,
    data: PathBuf,
}
impl Drop for OwnedWindow {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        if let (Ok(endpoint), Ok(token)) = (
            genyra_common::endpoint(&self.data),
            genyra_common::token(&self.data),
        ) {
            if let Ok(client) = reqwest::blocking::Client::builder()
                .timeout(Duration::from_secs(2))
                .no_proxy()
                .build()
            {
                let _ = client
                    .post(format!("{}/shutdown", endpoint.url))
                    .header("X-Snitch-Token", token)
                    .json(&json!({}))
                    .send();
            }
        }
    }
}
fn dispatch(expression: &str) {
    let result = Command::new("hyprctl")
        .args(["dispatch", expression])
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "hyprctl rejected {expression}: {}",
        String::from_utf8_lossy(&result.stdout)
    );
}
#[test]
#[ignore = "Requires active Lua Hyprland/Wayland; moves only its own synthetic test window"]
fn offscreen_window_still_answers_close_and_flushes_its_collector() {
    assert!(std::env::var_os("WAYLAND_DISPLAY").is_some());
    let temporary = tempfile::tempdir().unwrap();
    let binary = std::env::var_os("SNITCH_DESKTOP_TEST_BINARY")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_BIN_EXE_genyra-snitch-desktop")));
    let child = Command::new(binary)
        .args(["--demo", "--data-dir"])
        .arg(temporary.path())
        .env_remove("SNITCH_DATA_DIR")
        .env_remove("SNITCH_TOKEN")
        .env_remove("SNITCH_TLS_CERT")
        .env_remove("SNITCH_TLS_KEY")
        .env_remove("SNITCH_REPLAY_PCAP")
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap();
    let mut owned = OwnedWindow {
        child,
        data: temporary.path().into(),
    };
    let deadline = Instant::now() + Duration::from_secs(10);
    let address = loop {
        assert!(
            owned.child.try_wait().unwrap().is_none(),
            "UI exited before its window appeared"
        );
        let output = Command::new("hyprctl")
            .args(["-j", "clients"])
            .output()
            .unwrap();
        let clients: Value = serde_json::from_slice(&output.stdout).unwrap();
        if let Some(address) = clients
            .as_array()
            .unwrap()
            .iter()
            .find(|w| w["pid"] == owned.child.id())
            .and_then(|w| w["address"].as_str())
        {
            assert!(
                address.starts_with("0x") && address[2..].bytes().all(|b| b.is_ascii_hexdigit())
            );
            break address.to_string();
        }
        assert!(Instant::now() < deadline, "native window did not appear");
        std::thread::sleep(Duration::from_millis(200));
    };
    std::thread::sleep(Duration::from_millis(500));
    let selector = format!("address:{address}");
    dispatch(&format!("hl.dsp.window.move({{window=\"{selector}\",workspace=\"special:genyra-check-{}\",follow=false}})",owned.child.id()));
    std::thread::sleep(Duration::from_secs(8));
    assert!(
        owned.child.try_wait().unwrap().is_none(),
        "UI died while off-screen"
    );
    dispatch(&format!("hl.dsp.window.close({{window=\"{selector}\"}})"));
    let deadline = Instant::now() + Duration::from_secs(4);
    loop {
        if let Some(status) = owned.child.try_wait().unwrap() {
            assert!(status.success());
            break;
        }
        assert!(
            Instant::now() < deadline,
            "off-screen UI stopped answering Wayland close requests"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(
        genyra_common::endpoint(temporary.path()).is_err(),
        "UI did not flush and stop its owned collector"
    );
    assert!(genyra_common::Instance::acquire(temporary.path()).is_ok());
}
