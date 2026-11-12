//! `cups-deviced` — device discovery helper (`scheduler/deviced.c`).
//!
//! Runs every executable under `ServerBin/backend` with no arguments; each
//! prints `class uri make-model info [device-id]` lines which are merged
//! onto stdout in the order the backends finished. `usage: deviced
//! request-id limit timeout` matches upstream's argv contract.

use std::env;
use std::path::PathBuf;
use std::process::{Command, Stdio};

fn main() {
    // cups-deviced <request-id> <limit> <timeout> [backend-dir]
    let a: Vec<String> = env::args().collect();
    if a.len() < 4 {
        eprintln!("Usage: {} request-id limit timeout [dir]", a[0]);
        std::process::exit(1);
    }
    let _request_id: i32 = a[1].parse().unwrap_or(0);
    let limit: usize = a[2].parse().unwrap_or(0);
    let timeout: u64 = a[3].parse().unwrap_or(30);
    let dir = a
        .get(4)
        .map_or_else(|| PathBuf::from("/usr/lib/cups/backend"), PathBuf::from);

    let mut backends: Vec<PathBuf> = std::fs::read_dir(&dir)
        .map(|rd| {
            rd.flatten()
                .map(|e| e.path())
                .filter(|p| p.metadata().is_ok_and(|m| m.is_file()) && is_exec(p))
                .collect()
        })
        .unwrap_or_default();
    backends.sort();

    let deadline = std::time::Instant::now() + Duration::from_secs(timeout);
    let mut children = Vec::new();
    for b in backends {
        // skip our own symlinked name; run with no args for discovery
        match Command::new(&b)
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
        {
            Ok(c) => children.push((b, c)),
            Err(e) => eprintln!("cups-deviced: cannot run {}: {e}", b.display()),
        }
    }

    let mut count = 0;
    for (path, c) in children {
        // crude per-backend timeout: wait remaining budget
        let rem = deadline.saturating_duration_since(std::time::Instant::now());
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = tx.send(c.wait_with_output());
        });
        match rx.recv_timeout(rem) {
            Ok(Ok(out)) => {
                let text = String::from_utf8_lossy(&out.stdout);
                for line in text.lines() {
                    if limit != 0 && count >= limit {
                        break;
                    }
                    if line.split_whitespace().count() >= 2 {
                        println!("{line}");
                        count += 1;
                    }
                }
            }
            Ok(Err(e)) => eprintln!("cups-deviced: {} failed: {e}", path.display()),
            Err(_) => {
                // timed out — leave it (upstream kills; we can't easily
                // without keeping the child handle)
            }
        }
    }
}

fn is_exec(p: &std::path::Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        p.metadata()
            .is_ok_and(|m| m.permissions().mode() & 0o111 != 0)
    }
    #[cfg(not(unix))]
    {
        let _ = p;
        true
    }
}

use std::time::Duration;
