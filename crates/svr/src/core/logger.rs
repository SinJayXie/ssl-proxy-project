//! 带大小轮转的日志初始化。
//!
//! - 每次启动在 `log.dir` 下创建 `app-{YYYYMMDD-HHMMSS}.log`；
//! - 单个文件超过 `max_size` 字节后，关闭并打开新的 `app-{ts}.log`。

use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::path::PathBuf;
use std::sync::Arc;

use chrono::Local;
use parking_lot::Mutex;
use tracing_subscriber::prelude::*;
use tracing_subscriber::fmt::MakeWriter;
use tracing_subscriber::EnvFilter;

/// 进程级日志状态
struct RotatingFileState {
    log_dir: PathBuf,
    max_size: u64,
    current: Option<CurrentFile>,
}

struct CurrentFile {
    #[allow(dead_code)]
    path: PathBuf,
    file: File,
    written: u64,
}

impl RotatingFileState {
    fn open_new(&mut self) -> io::Result<()> {
        let ts = Local::now().format("%Y%m%d-%H%M%S").to_string();
        let path = self.log_dir.join(format!("app-{}.log", ts));
        let file = OpenOptions::new().create(true).append(true).open(&path)?;
        self.current = Some(CurrentFile {
            path,
            file,
            written: 0,
        });
        Ok(())
    }

    fn ensure_open(&mut self) -> io::Result<()> {
        if self.current.is_none() {
            self.open_new()?;
        }
        Ok(())
    }

    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.ensure_open()?;

        // 命中轮转阈值：关闭旧文件，新开一个
        if let Some(cur) = &self.current {
            if cur.written >= self.max_size {
                // 显式 drop 触发 flush
                self.current = None;
                self.open_new()?;
            }
        }

        let cur = self.current.as_mut().expect("just opened");
        let n = cur.file.write(buf)?;
        cur.written = cur.written.saturating_add(n as u64);
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        if let Some(cur) = &mut self.current {
            cur.file.flush()?;
        }
        Ok(())
    }
}

/// 共享的日志写入器（内部可克隆的句柄）
#[derive(Clone)]
pub struct RotatingFileWriter {
    inner: Arc<Mutex<RotatingFileState>>,
}

impl RotatingFileWriter {
    pub fn new(log_dir: PathBuf, max_size: u64) -> io::Result<Self> {
        if !log_dir.exists() {
            std::fs::create_dir_all(&log_dir)?;
        }
        let mut state = RotatingFileState {
            log_dir,
            max_size,
            current: None,
        };
        state.open_new()?;
        Ok(Self {
            inner: Arc::new(Mutex::new(state)),
        })
    }
}

/// 单次事件的 writer 句柄
pub struct FileWriter<'a> {
    inner: &'a RotatingFileWriter,
}

impl<'a> Write for FileWriter<'a> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.inner.inner.lock().write(buf)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.inner.inner.lock().flush()
    }
}

impl<'a> MakeWriter<'a> for RotatingFileWriter {
    type Writer = FileWriter<'a>;
    fn make_writer(&'a self) -> Self::Writer {
        FileWriter { inner: self }
    }
}

/// 初始化全局 tracing。
///
/// * 控制台 + 文件双输出；
/// * 文件按大小轮转；
/// * 当前进程内 RUST_LOG / EnvFilter 控制级别。
pub fn init(file_writer: RotatingFileWriter, level: &str) {
    let env_filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(level));

    let console_layer = tracing_subscriber::fmt::layer()
        .with_target(false)
        .with_writer(std::io::stdout);

    let file_layer = tracing_subscriber::fmt::layer()
        .with_target(false)
        .with_ansi(false)
        .with_writer(file_writer);

    tracing_subscriber::registry()
        .with(env_filter)
        .with(console_layer)
        .with(file_layer)
        .init();
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tracing_subscriber::fmt::MakeWriter;

    fn temp_dir(tag: &str) -> PathBuf {
        std::env::temp_dir().join(format!("ssl-proxy-log-{}-{}", tag, std::process::id()))
    }

    #[test]
    fn creates_missing_dir_and_writes_entry() {
        let dir = temp_dir("create");
        let _ = std::fs::remove_dir_all(&dir);

        let writer = RotatingFileWriter::new(dir.clone(), 1024).expect("create writer");
        {
            let mut w = writer.make_writer();
            w.write_all(b"hello-log\n").expect("write");
            w.flush().expect("flush");
        }

        let entries: Vec<_> = std::fs::read_dir(&dir)
            .expect("read log dir")
            .filter_map(|e| e.ok())
            .collect();
        assert_eq!(entries.len(), 1, "启动时应创建单个日志文件");

        let content = std::fs::read_to_string(entries[0].path()).expect("read log file");
        assert!(content.contains("hello-log"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn file_name_follows_expected_pattern() {
        let dir = temp_dir("naming");
        let _ = std::fs::remove_dir_all(&dir);

        let _writer = RotatingFileWriter::new(dir.clone(), 1024).expect("create writer");
        let name = std::fs::read_dir(&dir)
            .expect("read log dir")
            .filter_map(|e| e.ok())
            .next()
            .expect("one log file")
            .file_name()
            .to_string_lossy()
            .to_string();

        assert!(name.starts_with("app-"), "name={name}");
        assert!(name.ends_with(".log"), "name={name}");
        assert_eq!(name.len(), "app-20260101-000000.log".len(), "name={name}");

        let _ = std::fs::remove_dir_all(&dir);
    }
}
