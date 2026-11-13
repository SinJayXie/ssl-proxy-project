use std::fs::File;
use std::os::fd::AsRawFd;
use std::path::Path;

/// 单实例守卫：持有期间其他实例拿不到同一把 flock 锁。
/// 进程退出（包括崩溃）时由内核自动释放，不会留下死锁文件。
pub struct InstanceGuard {
    _file: File,
}

pub fn try_acquire(config_dir: &Path) -> Option<InstanceGuard> {
    std::fs::create_dir_all(config_dir).ok()?;
    let file = File::create(config_dir.join("instance.lock")).ok()?;
    let acquired = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0;
    acquired.then_some(InstanceGuard { _file: file })
}
