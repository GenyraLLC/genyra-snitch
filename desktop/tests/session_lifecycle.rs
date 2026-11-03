//! Optional graphical-session check of the real native window. Images and
//! databases are temporary, synthetic and removed after the test.
use std::{
    path::Path,
    process::{Command, Stdio},
    time::{Duration, Instant},
};
struct Background {
    data: std::path::PathBuf,
}
impl Drop for Background {
    fn drop(&mut self) {
        if let (Ok(endpoint), Ok(token)) = (
            genyra_common::endpoint(&self.data),
            genyra_common::token(&self.data),
        ) {
            if let Ok(client) = reqwest::blocking::Client::builder()
                .timeout(Duration::from_secs(3))
                .no_proxy()
                .build()
            {
                let _ = client
                    .post(format!("{}/shutdown", endpoint.url))
                    .header("X-Snitch-Token", token)
                    .json(&serde_json::json!({}))
                    .send();
            }
        }
    }
}
fn window(data: &Path, image: &Path, background: bool) {
    let mut command = Command::new(env!("CARGO_BIN_EXE_genyra-snitch-desktop"));
    command
        .args(["--demo", "--data-dir"])
        .arg(data)
        .arg("--render-check")
        .arg(image)
        .env_remove("SNITCH_TOKEN")
        .env_remove("SNITCH_DATA_DIR")
        .env_remove("SNITCH_TLS_CERT")
        .env_remove("SNITCH_TLS_KEY")
        .env_remove("SNITCH_REPLAY_PCAP")
        .stdout(Stdio::null())
        .stderr(Stdio::inherit());
    if background {
        command.arg("--background");
    }
    let mut child = command.spawn().unwrap();
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            assert!(status.success());
            break;
        }
        if Instant::now() > deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("native render/lifecycle check timed out");
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    assert!(
        image.metadata().unwrap().len() > 1024,
        "native renderer did not capture its frame"
    );
}
#[test]
#[ignore = "Requires a graphical session and the collector beside the desktop binary"]
fn closed_window_keeps_one_collector_and_reopening_attaches() {
    let temporary = tempfile::tempdir().unwrap();
    let data = temporary.path().join("background");
    let guard = Background { data: data.clone() };
    window(&data, &temporary.path().join("first.png"), true);
    let first = genyra_common::endpoint(&data).unwrap();
    assert!(genyra_common::Instance::acquire(&data).is_err());
    window(&data, &temporary.path().join("second.png"), false);
    let second = genyra_common::endpoint(&data).unwrap();
    assert_eq!(
        first.pid, second.pid,
        "reopening started a duplicate collector"
    );
    assert_eq!(first.url, second.url);
    drop(guard);
    for _ in 0..100 {
        if genyra_common::endpoint(&data).is_err() {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(genyra_common::Instance::acquire(&data).is_ok());
    let foreground = temporary.path().join("foreground");
    window(&foreground, &temporary.path().join("third.png"), false);
    assert!(
        genyra_common::endpoint(&foreground).is_err(),
        "default close left an unwanted background collector"
    );
    assert!(genyra_common::Instance::acquire(&foreground).is_ok());
}
