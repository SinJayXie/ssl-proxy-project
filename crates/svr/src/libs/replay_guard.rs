//! 首包重放防护：记录近期已使用的 MAC，拒绝重复首包。
//!
//! 时间窗（[`MAX_CLOCK_SKEW_SECS`]）只能限制"过期重放"，无法阻止窗口内把同一
//! 首包再发一次。mux 首包（hostLen = 0）一旦被重放，对端可直接获得一条已认证
//! 的复用连接并向任意目标 OPEN——因此必须记录已用 MAC。
//!
//! 实现为进程内 DashMap + TTL（默认与时钟窗一致）：
//! - `check_and_record` 原子地"查 + 写"，首次出现返回 `true`；
//! - 惰性清理：每 1024 次写入扫描一次过期项，避免长跑进程内存无界增长；
//! - 多实例部署需换成共享存储（Redis `SET NX EX`）。

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use dashmap::mapref::entry::Entry;
use dashmap::DashMap;

use crate::utils::protocol::MAX_CLOCK_SKEW_SECS;

/// 重放缓存表容量无关的清理间隔（写入次数）
const SWEEP_EVERY: u64 = 1024;

/// 重放防护表
pub struct ReplayGuard {
    seen: DashMap<[u8; 32], Instant>,
    ttl: Duration,
    writes: AtomicU64,
}

impl ReplayGuard {
    pub fn new(ttl: Duration) -> Self {
        Self {
            seen: DashMap::new(),
            ttl,
            writes: AtomicU64::new(0),
        }
    }

    /// 记录一个 MAC；返回 `true` 表示首次出现（放行），`false` 表示重放。
    pub fn check_and_record(&self, mac: [u8; 32]) -> bool {
        let now = Instant::now();
        if self.writes.fetch_add(1, Ordering::Relaxed) % SWEEP_EVERY == 0 {
            let ttl = self.ttl;
            self.seen.retain(|_, seen_at| seen_at.elapsed() < ttl);
        }

        match self.seen.entry(mac) {
            Entry::Occupied(mut entry) => {
                if entry.get().elapsed() < self.ttl {
                    false
                } else {
                    // 理论上已被清理；过期后同 MAC 可再次使用（时间窗也会放行）
                    entry.insert(now);
                    true
                }
            }
            Entry::Vacant(entry) => {
                entry.insert(now);
                true
            }
        }
    }
}

/// 进程级重放防护（TTL = 首包允许的时钟偏差）
pub fn accept(mac: [u8; 32]) -> bool {
    static GUARD: OnceLock<ReplayGuard> = OnceLock::new();
    GUARD
        .get_or_init(|| ReplayGuard::new(Duration::from_secs(MAX_CLOCK_SKEW_SECS)))
        .check_and_record(mac)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_use_is_accepted_and_replay_is_rejected() {
        let guard = ReplayGuard::new(Duration::from_secs(60));
        let mac = [7u8; 32];
        assert!(guard.check_and_record(mac));
        assert!(!guard.check_and_record(mac), "同一 MAC 第二次应判定为重放");
    }

    #[test]
    fn distinct_macs_are_independent() {
        let guard = ReplayGuard::new(Duration::from_secs(60));
        assert!(guard.check_and_record([1u8; 32]));
        assert!(guard.check_and_record([2u8; 32]));
        assert!(!guard.check_and_record([1u8; 32]));
    }

    #[test]
    fn expired_entry_is_accepted_again() {
        let guard = ReplayGuard::new(Duration::from_millis(10));
        let mac = [3u8; 32];
        assert!(guard.check_and_record(mac));
        std::thread::sleep(Duration::from_millis(25));
        assert!(guard.check_and_record(mac), "TTL 过期后应允许再次使用");
    }
}
