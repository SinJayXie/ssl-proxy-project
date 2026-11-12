use std::fs::File;
use std::io::{self, Write};
use std::path::Path;
use std::sync::Mutex;

/// Writer that tees output to stdout and a file.
struct TeeWriter {
    file: Mutex<File>,
}

impl Write for TeeWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        io::stdout().write_all(buf)?;
        self.file.lock().unwrap().write_all(buf)?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        io::stdout().flush()?;
        self.file.lock().unwrap().flush()
    }
}

/// Initialize logging to stdout and `<config_dir>/app.log`.
pub fn init(config_dir: &Path) {
    if let Err(err) = std::fs::create_dir_all(config_dir) {
        eprintln!("Failed to create config dir {config_dir:?}: {err}");
    }

    let log_path = config_dir.join("app.log");
    let log_file = match File::create(&log_path) {
        Ok(file) => file,
        Err(err) => {
            eprintln!("Failed to create log file {log_path:?}: {err}");
            return;
        }
    };

    let tee = TeeWriter {
        file: Mutex::new(log_file),
    };

    let _ = env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .format(|buf, record| {
            writeln!(
                buf,
                "[{} {}] {}",
                buf.timestamp_millis(),
                record.level(),
                record.args()
            )
        })
        .target(env_logger::Target::Pipe(Box::new(tee)))
        .try_init();
}
