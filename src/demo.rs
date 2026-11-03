//! Explicit synthetic traffic mode. It never captures or enforces host policy.
use crate::{process::Table, state::Engine};
use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};
pub fn enabled() -> bool {
    std::env::var("SNITCH_DEMO").as_deref() == Ok("1")
        || std::env::args().any(|arg| arg == "--demo")
}
pub fn run(engine: Arc<Mutex<Engine>>, stop: Arc<AtomicBool>) {
    let local = "192.0.2.1".parse().unwrap();
    let table = Table::default();
    engine.lock().unwrap().local_ips.insert(local);
    let targets: [([u8; 4], u16, &str); 3] = [
        ([1, 1, 1, 1], 443, "cloudflare-dns.com"),
        ([8, 8, 8, 8], 53, "dns.google"),
        ([93, 184, 216, 34], 443, "example.com"),
    ];
    while !stop.load(Ordering::Relaxed) {
        {
            let mut e = engine.lock().unwrap();
            if e.capturing {
                e.error = None;
                for (i, (ip, port, name)) in targets.iter().enumerate() {
                    let mut frame = vec![0u8; 14 + 20 + 8 + 128];
                    frame[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
                    frame[14] = 0x45;
                    frame[16..18].copy_from_slice(&156u16.to_be_bytes());
                    frame[22] = 64;
                    frame[23] = 17;
                    frame[26..30].copy_from_slice(&[192, 0, 2, 1]);
                    frame[30..34].copy_from_slice(ip);
                    frame[34..36].copy_from_slice(&(42000 + i as u16).to_be_bytes());
                    frame[36..38].copy_from_slice(&(*port).to_be_bytes());
                    frame[38..40].copy_from_slice(&136u16.to_be_bytes());
                    e.packet(&frame, frame.len() as u32, 1, &table);
                    e.learn_ptr(
                        std::net::Ipv4Addr::from(*ip).into(),
                        *port,
                        "UDP",
                        Some((*name).into()),
                    );
                }
                e.learn_device(
                    "192.168.1.25".parse().unwrap(),
                    Some("00:1A:11:00:00:25".into()),
                    Some("Demo device".into()),
                );
                e.clear_wire_frames();
                e.tick();
            }
        }
        crate::interruptible_sleep(&stop, Duration::from_millis(250));
    }
}
