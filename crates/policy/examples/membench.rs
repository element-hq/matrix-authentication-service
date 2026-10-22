// Copyright 2026 Element Creations Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

//! Measures the memory and time cost of loading and evaluating the policy.
//!
//! Usage:
//!   membench jit|jit-serial|winch|winch-serial <policy.wasm>
//!   membench precompile <policy.wasm> <out.cwasm>
//!   membench cwasm-file <policy.cwasm>
//!   membench cwasm-bytes <policy.cwasm>
//!
//! Each mode runs in its own process, as the high-water mark is per-process.

#![allow(clippy::print_stdout, clippy::too_many_lines, unsafe_code)]

use std::time::{Duration, Instant};

use mas_policy::{EvaluationResult, RegisterInput, RegistrationMethod, Requester};
use opa_wasm::{
    Runtime,
    wasmtime::{Config, Engine, Module, OptLevel, Store, Strategy},
};

const ITERATIONS: usize = 1000;
const ENTRYPOINTS: [&str; 5] = [
    "register/violation",
    "client_registration/violation",
    "authorization_grant/violation",
    "compat_login/violation",
    "email/violation",
];

/// Memory figures, in KiB
#[derive(Default, Clone, Copy)]
struct Sample {
    rss: u64,
    hwm: u64,
    anon: Option<u64>,
    file: Option<u64>,
    private_dirty: Option<u64>,
    threads: Option<u64>,
}

#[cfg(target_os = "linux")]
fn sample() -> Sample {
    fn field(text: &str, name: &str) -> Option<u64> {
        text.lines()
            .find(|l| l.starts_with(name))
            .and_then(|l| l.split_whitespace().nth(1))
            .and_then(|v| v.parse().ok())
    }
    let status = std::fs::read_to_string("/proc/self/status").unwrap();
    let rollup = std::fs::read_to_string("/proc/self/smaps_rollup").unwrap();
    let rss = field(&rollup, "Rss:").unwrap();
    let anon = field(&rollup, "Anonymous:").unwrap();
    Sample {
        rss: field(&status, "VmRSS:").unwrap(),
        hwm: field(&status, "VmHWM:").unwrap(),
        anon: Some(anon),
        file: Some(rss - anon),
        private_dirty: field(&rollup, "Private_Dirty:"),
        threads: u64::try_from(std::fs::read_dir("/proc/self/task").unwrap().count()).ok(),
    }
}

#[cfg(target_os = "macos")]
fn sample() -> Sample {
    let mut info: libc::proc_taskinfo = unsafe { std::mem::zeroed() };
    let size = i32::try_from(std::mem::size_of::<libc::proc_taskinfo>()).unwrap();
    let ret = unsafe {
        libc::proc_pidinfo(
            libc::getpid(),
            libc::PROC_PIDTASKINFO,
            0,
            (&raw mut info).cast(),
            size,
        )
    };
    assert_eq!(ret, size);
    let mut usage: libc::rusage = unsafe { std::mem::zeroed() };
    unsafe { libc::getrusage(libc::RUSAGE_SELF, &raw mut usage) };
    Sample {
        rss: info.pti_resident_size / 1024,
        // ru_maxrss is in bytes on macOS
        hwm: u64::try_from(usage.ru_maxrss).unwrap() / 1024,
        ..Sample::default()
    }
}

struct Report {
    mode: String,
    rows: Vec<(&'static str, Sample, Option<Duration>)>,
}

impl Report {
    fn point(&mut self, name: &'static str, elapsed: Option<Duration>) {
        self.rows.push((name, sample(), elapsed));
    }

    fn print(&self) {
        let opt = |v: Option<u64>| v.map_or_else(|| "-".to_owned(), |v| v.to_string());
        println!("mode={}", self.mode);
        println!(
            "{:<28} {:>9} {:>9} {:>9} {:>9} {:>9} {:>7} {:>12}",
            "checkpoint", "rss_kib", "hwm_kib", "anon_kib", "file_kib", "pdirty", "threads", "time"
        );
        for (name, s, t) in &self.rows {
            println!(
                "{:<28} {:>9} {:>9} {:>9} {:>9} {:>9} {:>7} {:>12}",
                name,
                s.rss,
                s.hwm,
                opt(s.anon),
                opt(s.file),
                opt(s.private_dirty),
                opt(s.threads),
                t.map_or_else(|| "-".to_owned(), |t| format!("{t:.2?}")),
            );
        }
    }
}

fn base_config() -> Config {
    let mut config = Config::default();
    config.cranelift_opt_level(OptLevel::SpeedAndSize);
    config
}

async fn instantiate_and_evaluate(
    engine: &Engine,
    module: &Module,
    data: &serde_json::Value,
    input: &RegisterInput<'_>,
) -> anyhow::Result<bool> {
    let mut store = Store::new(engine, ());
    let runtime = Runtime::new(&mut store, module).await?;
    let entrypoints = runtime.entrypoints();
    for e in ENTRYPOINTS {
        anyhow::ensure!(entrypoints.contains(e), "missing entrypoint {e}");
    }
    let policy = runtime.with_data(&mut store, data).await?;
    let [res]: [EvaluationResult; 1] = policy
        .evaluate(&mut store, "register/violation", input)
        .await?;
    Ok(res.valid())
}

async fn run(mode: &str, path: &str) -> anyhow::Result<()> {
    let mut report = Report {
        mode: mode.to_owned(),
        rows: Vec::new(),
    };
    report.point("start", None);

    println!("artifact_bytes={}", std::fs::metadata(path)?.len());
    let bytes = if mode == "cwasm-file" {
        Vec::new()
    } else {
        std::fs::read(path)?
    };
    report.point("after read", None);

    let t = Instant::now();
    let mut config = base_config();
    if mode.starts_with("winch") {
        config.strategy(Strategy::Winch);
    }
    if mode.ends_with("-serial") {
        config.parallel_compilation(false);
    }
    let engine = Engine::new(&config)?;
    report.point("after Engine::new", Some(t.elapsed()));

    let t = Instant::now();
    let module = match mode {
        "jit" | "jit-serial" | "winch" | "winch-serial" => {
            let engine = engine.clone();
            tokio::task::spawn_blocking(move || Module::new(&engine, bytes)).await??
        }
        "cwasm-file" => {
            // SAFETY: the file is produced by `membench precompile`.
            unsafe { Module::deserialize_file(&engine, path)? }
        }
        "cwasm-bytes" => {
            // SAFETY: the file is produced by `membench precompile`.
            let module = unsafe { Module::deserialize(&engine, &bytes)? };
            drop(bytes);
            module
        }
        _ => anyhow::bail!("unknown mode {mode}"),
    };
    report.point("after module load", Some(t.elapsed()));

    let data = serde_json::json!({ "server_name": "example.com", "session_limit": null });
    let input = RegisterInput {
        registration_method: RegistrationMethod::Password,
        username: "hello",
        email: Some("hello@example.com"),
        requester: Requester {
            ip_address: None,
            user_agent: None,
        },
    };

    let t = Instant::now();
    let valid = instantiate_and_evaluate(&engine, &module, &data, &input).await?;
    anyhow::ensure!(valid, "unexpected policy result");
    report.point("after first instantiate", Some(t.elapsed()));

    let t = Instant::now();
    for _ in 0..ITERATIONS {
        instantiate_and_evaluate(&engine, &module, &data, &input).await?;
    }
    let elapsed = t.elapsed();
    report.point("after 1000 cycles", Some(elapsed));
    println!(
        "per_cycle={:.1?}",
        elapsed / u32::try_from(ITERATIONS).unwrap()
    );

    drop(module);
    drop(engine);
    report.point("after drop", None);

    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    {
        unsafe { libc::malloc_trim(0) };
        report.point("after malloc_trim", None);
    }

    report.print();
    Ok(())
}

fn precompile(input: &str, output: &str) -> anyhow::Result<()> {
    let bytes = std::fs::read(input)?;
    let engine = Engine::new(&base_config())?;
    let t = Instant::now();
    let cwasm = engine.precompile_module(&bytes)?;
    println!(
        "precompile: {} -> {} bytes in {:.2?}",
        bytes.len(),
        cwasm.len(),
        t.elapsed()
    );
    std::fs::write(output, cwasm)?;
    Ok(())
}

fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let mode = args.get(1).map(String::as_str).unwrap_or_default();
    let path = args.get(2).map_or("policies/policy.wasm", String::as_str);

    if mode == "precompile" {
        return precompile(path, args.get(3).map_or("policy.cwasm", String::as_str));
    }

    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(run(mode, path))
}
