//! Minimal file logger: `logs\gui.log` in the local folder, rotated to `gui.log.1` at 1 MB,
//! level from `WOL_MANAGER_LOG` (default `info`). Falls back to `%TEMP%\wol-manager` when the
//! log folder is not writable. The panic hook logs the panic and shows a message box.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};

use log::{LevelFilter, Log, Metadata, Record};

use crate::texts::GuiText;

/// Rotation threshold.
pub const MAX_LOG_BYTES: u64 = 1024 * 1024;
/// Log file name.
pub const LOG_FILE: &str = "gui.log";

/// Level from the `WOL_MANAGER_LOG` value.
pub fn level_from(value: Option<&str>) -> LevelFilter {
    match value.map(|v| v.trim().to_ascii_lowercase()).as_deref() {
        Some("off") => LevelFilter::Off,
        Some("error") => LevelFilter::Error,
        Some("warn" | "warning") => LevelFilter::Warn,
        Some("debug") => LevelFilter::Debug,
        Some("trace") => LevelFilter::Trace,
        _ => LevelFilter::Info,
    }
}

/// `true` when writing `len` more bytes to a file of `size` bytes needs a rotation first.
pub fn needs_rotation(size: u64, len: u64, limit: u64) -> bool {
    size > 0 && size.saturating_add(len) > limit
}

struct LogFile {
    path: PathBuf,
    file: Option<File>,
    size: u64,
    limit: u64,
}

impl LogFile {
    fn open(path: &Path, limit: u64) -> std::io::Result<LogFile> {
        let file = OpenOptions::new().create(true).append(true).open(path)?;
        let size = file.metadata().map(|m| m.len()).unwrap_or(0);
        Ok(LogFile {
            path: path.to_path_buf(),
            file: Some(file),
            size,
            limit,
        })
    }

    fn rotated(&self) -> PathBuf {
        let mut s = self.path.clone().into_os_string();
        s.push(".1");
        PathBuf::from(s)
    }

    fn write_line(&mut self, line: &str) {
        let len = line.len() as u64;
        if needs_rotation(self.size, len, self.limit) {
            self.file.take();
            let rotated = self.rotated();
            let _ = std::fs::remove_file(&rotated);
            let _ = std::fs::rename(&self.path, &rotated);
            self.size = 0;
            self.file = OpenOptions::new()
                .create(true)
                .append(true)
                .open(&self.path)
                .ok();
        }
        if let Some(f) = self.file.as_mut()
            && f.write_all(line.as_bytes()).is_ok()
        {
            self.size += len;
        }
    }
}

struct FileLogger {
    level: LevelFilter,
    out: Mutex<LogFile>,
    echo: bool,
}

fn own_target(target: &str) -> bool {
    target.starts_with("wol_manager") || target.starts_with("wol_core")
}

impl Log for FileLogger {
    fn enabled(&self, m: &Metadata<'_>) -> bool {
        // Other crates (winit, slint, …) only from `warn` unless tracing everything.
        let max = if own_target(m.target()) || self.level == LevelFilter::Trace {
            self.level
        } else {
            self.level.min(LevelFilter::Warn)
        };
        m.level() <= max
    }

    fn log(&self, r: &Record<'_>) {
        if !self.enabled(r.metadata()) {
            return;
        }
        let line = format!(
            "{} {:<5} [{}] {}\r\n",
            timestamp(),
            r.level(),
            r.target(),
            r.args()
        );
        if self.echo {
            eprint!("{line}");
        }
        if let Ok(mut out) = self.out.lock() {
            out.write_line(&line);
        }
    }

    fn flush(&self) {
        if let Ok(mut out) = self.out.lock()
            && let Some(f) = out.file.as_mut()
        {
            let _ = f.flush();
        }
    }
}

/// Local time "YYYY-MM-DD hh:mm:ss.mmm".
pub fn timestamp() -> String {
    let t = local_time();
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02}.{:03}",
        t.wYear, t.wMonth, t.wDay, t.wHour, t.wMinute, t.wSecond, t.wMilliseconds
    )
}

/// Local time "hh:mm:ss" (status bar "last checked").
pub fn clock() -> String {
    let t = local_time();
    format!("{:02}:{:02}:{:02}", t.wHour, t.wMinute, t.wSecond)
}

fn local_time() -> windows_sys::Win32::Foundation::SYSTEMTIME {
    // SAFETY: GetLocalTime fills the struct.
    unsafe {
        let mut t = std::mem::zeroed();
        windows_sys::Win32::System::SystemInformation::GetLocalTime(&mut t);
        t
    }
}

/// Opens the log file in `dir` (creating it), or in the fallback folder. Returns its path.
fn open_in(dirs: &[PathBuf]) -> Option<LogFile> {
    for dir in dirs {
        if std::fs::create_dir_all(dir).is_err() {
            continue;
        }
        if let Ok(f) = LogFile::open(&dir.join(LOG_FILE), MAX_LOG_BYTES) {
            return Some(f);
        }
    }
    None
}

/// Installs the logger. `dir` = the log folder of the location. Returns the log file path
/// (`None` when no folder was writable: logging is then disabled).
pub fn init(dir: &Path) -> Option<PathBuf> {
    let level = level_from(std::env::var(wol_core::consts::ENV_LOG).ok().as_deref());
    let file = open_in(&[
        dir.to_path_buf(),
        wol_core::store::ConfigLocation::fallback_log_dir(),
    ])?;
    let path = file.path.clone();
    let logger = FileLogger {
        level,
        out: Mutex::new(file),
        echo: cfg!(debug_assertions),
    };
    if log::set_boxed_logger(Box::new(logger)).is_ok() {
        log::set_max_level(level);
    }
    Some(path)
}

static PANICKED: AtomicBool = AtomicBool::new(false);

/// Logs panics and shows a message box (once).
pub fn install_panic_hook(log_path: Option<PathBuf>, lang: wol_core::i18n::Lang) {
    let previous = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let bt = std::backtrace::Backtrace::force_capture();
        let thread = std::thread::current();
        log::error!(
            "panic on thread {}: {info}\n{bt}",
            thread.name().unwrap_or("?")
        );
        log::logger().flush();
        if !PANICKED.swap(true, Ordering::SeqCst) {
            let where_ = log_path
                .as_ref()
                .map(|p| p.display().to_string())
                .unwrap_or_default();
            crate::shell::message_box(&GuiText::Crashed(where_).text(lang), true);
        }
        previous(info);
    }));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn levels() {
        assert_eq!(level_from(None), LevelFilter::Info);
        assert_eq!(level_from(Some("DEBUG")), LevelFilter::Debug);
        assert_eq!(level_from(Some(" warn ")), LevelFilter::Warn);
        assert_eq!(level_from(Some("bogus")), LevelFilter::Info);
        assert_eq!(level_from(Some("off")), LevelFilter::Off);
    }

    #[test]
    fn rotation_rule() {
        assert!(
            !needs_rotation(0, 2_000_000, MAX_LOG_BYTES),
            "never rotate an empty file"
        );
        assert!(!needs_rotation(100, 100, MAX_LOG_BYTES));
        assert!(needs_rotation(MAX_LOG_BYTES - 10, 11, MAX_LOG_BYTES));
    }

    #[test]
    fn rotates_to_dot_one() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(LOG_FILE);
        let mut f = LogFile::open(&path, 64).unwrap();
        f.write_line(&"a".repeat(40));
        f.write_line(&"b".repeat(40));
        f.write_line(&"c".repeat(10));
        drop(f);
        assert_eq!(
            std::fs::read_to_string(dir.path().join("gui.log.1")).unwrap(),
            "a".repeat(40)
        );
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            format!("{}{}", "b".repeat(40), "c".repeat(10))
        );
        // Reopen appends and continues counting.
        let f = LogFile::open(&path, 64).unwrap();
        assert_eq!(f.size, 50);
    }

    #[test]
    fn falls_back_when_the_folder_is_unusable() {
        let dir = tempfile::tempdir().unwrap();
        let blocker = dir.path().join("file");
        std::fs::write(&blocker, "x").unwrap();
        let fallback = dir.path().join("fallback");
        let f = open_in(&[blocker.join("logs"), fallback.clone()]).unwrap();
        assert_eq!(f.path, fallback.join(LOG_FILE));
    }

    #[test]
    fn clock_format() {
        let c = clock();
        assert_eq!(c.len(), 8);
        assert_eq!(&c[2..3], ":");
        assert_eq!(timestamp().len(), 23);
    }
}
