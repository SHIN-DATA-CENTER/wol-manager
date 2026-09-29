//! Test helper for `wolm gui` (tests/cli.rs), never shipped: stands in for wol-manager.exe
//! and keeps running like the real app in the notification area. It writes `running` into
//! the folder given with `--config-dir`, and exits (writing `exited`) when a file `stop`
//! appears there, or after 30 s.

use std::path::PathBuf;
use std::time::{Duration, Instant};

fn main() {
    let mut args = std::env::args_os().skip(1);
    let mut dir: Option<PathBuf> = None;
    while let Some(a) = args.next() {
        if a == "--config-dir" {
            dir = args.next().map(PathBuf::from);
        }
    }
    let Some(dir) = dir else { return };
    let _ = std::fs::write(dir.join("running"), b"");
    let deadline = Instant::now() + Duration::from_secs(30);
    while Instant::now() < deadline && !dir.join("stop").exists() {
        std::thread::sleep(Duration::from_millis(50));
    }
    let _ = std::fs::write(dir.join("exited"), b"");
}
