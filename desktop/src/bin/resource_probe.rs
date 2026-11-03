//! Sustained per-process resource measurements, without recording arguments,
//! connections, tokens or packet data. CPU is percent of one logical core.
use std::{
    collections::HashMap,
    time::{Duration, Instant},
};
use sysinfo::{Pid, ProcessRefreshKind, ProcessesToUpdate, System};
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args().collect();
    let option = |name: &str| {
        args.windows(2)
            .find(|a| a[0] == name)
            .map(|a| a[1].as_str())
    };
    let pids: Vec<_> = option("--pids")
        .ok_or("Usage: genyra-resource-probe --pids PID,PID --seconds 1800 --interval 10")?
        .split(',')
        .map(|s| s.parse::<u32>().map(Pid::from_u32))
        .collect::<Result<_, _>>()?;
    let duration = option("--seconds")
        .unwrap_or("1800")
        .parse::<u64>()?
        .clamp(1, 86400);
    let interval = option("--interval")
        .unwrap_or("10")
        .parse::<u64>()?
        .clamp(1, 60);
    let kind = ProcessRefreshKind::nothing().with_cpu().with_memory();
    let mut system = System::new();
    system.refresh_processes_specifics(ProcessesToUpdate::Some(&pids), true, kind);
    let identities: HashMap<_, _> = pids
        .iter()
        .filter_map(|pid| system.process(*pid).map(|p| (*pid, p.start_time())))
        .collect();
    if identities.len() != pids.len() {
        return Err("One or more process IDs do not exist".into());
    }
    println!("elapsed_s,pid,name,cpu_one_core_percent,rss_bytes");
    let start = Instant::now();
    loop {
        let remaining = Duration::from_secs(duration).saturating_sub(start.elapsed());
        if remaining.is_zero() {
            break;
        }
        std::thread::sleep(Duration::from_secs(interval).min(remaining));
        system.refresh_processes_specifics(ProcessesToUpdate::Some(&pids), true, kind);
        let mut alive = 0;
        for pid in &pids {
            if let Some(process) = system
                .process(*pid)
                .filter(|p| Some(&p.start_time()) == identities.get(pid))
            {
                alive += 1;
                // Names cannot introduce CSV rows; arguments are never read.
                let name = process
                    .name()
                    .to_string_lossy()
                    .replace([',', '\n', '\r'], "_");
                println!(
                    "{:.3},{},{},{:.3},{}",
                    start.elapsed().as_secs_f64(),
                    pid.as_u32(),
                    name,
                    process.cpu_usage(),
                    process.memory()
                );
            }
        }
        if alive == 0 {
            break;
        }
    }
    Ok(())
}
