//! Run the real collector against an owned local model fixture. This catches
//! concurrent inference spawning that a cache-only unit test cannot detect.
use serde_json::{json, Value};
use std::{
    io::{BufRead, BufReader, Read, Write},
    net::{TcpListener, TcpStream},
    process::{Child, Command, Stdio},
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};
struct Collector(Child);
impl Drop for Collector {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
struct Model {
    stop: Arc<AtomicBool>,
    port: u16,
    thread: Option<std::thread::JoinHandle<()>>,
    max: Arc<AtomicUsize>,
    calls: Arc<AtomicUsize>,
}
impl Drop for Model {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        let _ = TcpStream::connect(("127.0.0.1", self.port));
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}
fn model_request(
    mut stream: TcpStream,
    active: Arc<AtomicUsize>,
    max: Arc<AtomicUsize>,
    calls: Arc<AtomicUsize>,
) -> std::io::Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut line = String::new();
    reader.read_line(&mut line)?;
    let generate = line.starts_with("POST /api/generate ");
    let mut size = 0;
    loop {
        line.clear();
        reader.read_line(&mut line)?;
        if line == "\r\n" || line.is_empty() {
            break;
        }
        if let Some((key, value)) = line.split_once(':') {
            if key.eq_ignore_ascii_case("content-length") {
                size = value.trim().parse::<usize>().unwrap();
            }
        }
    }
    assert!(size < 16384);
    let mut body = vec![0; size];
    reader.read_exact(&mut body)?;
    let response = if generate {
        let n = active.fetch_add(1, Ordering::SeqCst) + 1;
        max.fetch_max(n, Ordering::SeqCst);
        calls.fetch_add(1, Ordering::SeqCst);
        std::thread::sleep(Duration::from_millis(100));
        active.fetch_sub(1, Ordering::SeqCst);
        json!({"response":"A local fixture explanation.","done":true})
    } else {
        json!({"models":[{"name":"fixture"}]})
    }
    .to_string();
    write!(stream,"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",response.len(),response)
}
impl Model {
    fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let stop = Arc::new(AtomicBool::new(false));
        let active = Arc::new(AtomicUsize::new(0));
        let max = Arc::new(AtomicUsize::new(0));
        let calls = Arc::new(AtomicUsize::new(0));
        let (stopping, busy, maximum, count) = (stop.clone(), active, max.clone(), calls.clone());
        let thread = std::thread::spawn(move || {
            let mut workers = vec![];
            for stream in listener.incoming() {
                if stopping.load(Ordering::Relaxed) {
                    break;
                }
                let Ok(stream) = stream else {
                    break;
                };
                let (active, max, calls) = (busy.clone(), maximum.clone(), count.clone());
                workers.push(std::thread::spawn(move || {
                    let _ = model_request(stream, active, max, calls);
                }));
            }
            for worker in workers {
                let _ = worker.join();
            }
        });
        Self {
            stop,
            port,
            thread: Some(thread),
            max,
            calls,
        }
    }
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn concurrent_explanations_respect_one_model_memory_budget() {
    let model = Model::start();
    let dir = tempfile::tempdir().unwrap();
    let reserve = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = reserve.local_addr().unwrap().port();
    drop(reserve);
    let token = "test-only-native-model-budget-token";
    let child = Command::new(env!("CARGO_BIN_EXE_genyra-snitch"))
        .args(["--demo", "--port", &port.to_string()])
        .env("SNITCH_DATA_DIR", dir.path())
        .env("SNITCH_TOKEN", token)
        .env("SNITCH_BIND", "127.0.0.1")
        .env_remove("SNITCH_TLS_CERT")
        .env_remove("SNITCH_TLS_KEY")
        .env_remove("SNITCH_REPLAY_PCAP")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut collector = Collector(child);
    let client = reqwest::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(10))
        .build()
        .unwrap();
    let base = format!("http://127.0.0.1:{port}");
    let mut ready = false;
    for _ in 0..100 {
        if client
            .get(format!("{base}/diagnostics"))
            .header("X-Snitch-Token", token)
            .send()
            .await
            .is_ok_and(|r| r.status().is_success())
        {
            ready = true;
            break;
        }
        assert!(
            collector.0.try_wait().unwrap().is_none(),
            "collector exited before startup"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(ready, "collector startup timed out");
    client.post(format!("{base}/settings")).header("X-Snitch-Token",token).json(&json!({"settings":{"slm_enabled":true,"slm_mode":"ollama","slm_model":"fixture","slm_endpoint":format!("http://127.0.0.1:{}",model.port)}})).send().await.unwrap().error_for_status().unwrap();
    let mut requests = tokio::task::JoinSet::new();
    for sample in 0..8 {
        let client = client.clone();
        let base = base.clone();
        requests.spawn(async move {
            client
                .post(format!("{base}/security/explain"))
                .header("X-Snitch-Token", token)
                .json(&json!({"type":"NEW_HOST","detail":{"sample":sample},"lang":"en"}))
                .send()
                .await
                .unwrap()
                .error_for_status()
                .unwrap()
                .json::<Value>()
                .await
                .unwrap()
        });
    }
    while let Some(result) = requests.join_next().await {
        assert_eq!(result.unwrap()["llm"], "A local fixture explanation.");
    }
    assert_eq!(model.calls.load(Ordering::SeqCst), 8);
    assert_eq!(
        model.max.load(Ordering::SeqCst),
        1,
        "parallel requests must not multiply model memory"
    );
}
