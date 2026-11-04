//! Opt-in numeric UI diagnostics; never records traffic, labels or inputs.
use eframe::egui;
use std::{
    fs::OpenOptions,
    io::{self, BufWriter, Write},
    path::Path,
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc, Arc,
    },
    thread,
    time::{Duration, Instant},
};

pub(super) struct Probe {
    output: BufWriter<std::fs::File>,
    started: Instant,
    previous: Instant,
    pings: mpsc::Receiver<Instant>,
    stop: Arc<AtomicBool>,
    worker: Option<thread::JoinHandle<()>>,
}

impl Probe {
    pub(super) fn new(path: &Path, ctx: egui::Context) -> io::Result<Self> {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut output = BufWriter::new(options.open(path)?);
        writeln!(
            output,
            "elapsed_s,frame_interval_ms,previous_frame_cpu_ms,repaint_latency_ms"
        )?;
        let (send, pings) = mpsc::sync_channel(1);
        let stop = Arc::new(AtomicBool::new(false));
        let stopping = stop.clone();
        let worker = thread::Builder::new()
            .name("ui-repaint-probe".into())
            .spawn(move || {
                while !stopping.load(Ordering::Relaxed) {
                    thread::park_timeout(Duration::from_secs(1));
                    if stopping.load(Ordering::Relaxed) {
                        break;
                    }
                    if send.try_send(Instant::now()).is_ok() {
                        ctx.request_repaint();
                    }
                }
            })?;
        let now = Instant::now();
        Ok(Self {
            output,
            started: now,
            previous: now,
            pings,
            stop,
            worker: Some(worker),
        })
    }

    pub(super) fn frame(&mut self, previous_cpu_s: Option<f32>) {
        let now = Instant::now();
        let latency = self
            .pings
            .try_recv()
            .ok()
            .map(|sent| format!("{:.6}", now.duration_since(sent).as_secs_f64() * 1000.))
            .unwrap_or_default();
        let cpu = previous_cpu_s
            .map(|seconds| format!("{:.6}", seconds * 1000.))
            .unwrap_or_default();
        // Buffered, bounded memory: one numeric row per actual egui update.
        let _ = writeln!(
            self.output,
            "{:.6},{:.6},{},{}",
            now.duration_since(self.started).as_secs_f64(),
            now.duration_since(self.previous).as_secs_f64() * 1000.,
            cpu,
            latency
        );
        self.previous = now;
    }
}

impl Drop for Probe {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(worker) = self.worker.take() {
            worker.thread().unpark();
            let _ = worker.join();
        }
        let _ = self.output.flush();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn diagnostics_preserve_existing_files_and_flush_on_close() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("frames.csv");
        let mut probe = Probe::new(&path, egui::Context::default()).unwrap();
        probe.frame(Some(0.001));
        drop(probe);
        let original = std::fs::read(&path).unwrap();
        assert!(String::from_utf8_lossy(&original).contains("1.000000"));
        assert!(Probe::new(&path, egui::Context::default()).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), original);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }
}
