//! 内存级 IP 限流 + 黑名单（基于 DashMap，并发安全）

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use dashmap::DashMap;

#[derive(Debug, Clone, Copy)]
pub struct RateLimitConfig {
    pub max_requests: u32,
    pub rate_time: Duration,
    pub black_time: Duration,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            max_requests: 300,
            rate_time: Duration::from_secs(60),
            black_time: Duration::from_secs(600),
        }
    }
}

#[derive(Debug)]
struct RateRecord {
    /// 周期起始时间（毫秒）
    time_ms: u64,
    /// 周期内累计次数
    count: u32,
}

/// 并发安全的 IP 限流器
#[derive(Clone)]
pub struct RateLimit {
    records: Arc<DashMap<String, RateRecord>>,
    blacklist: Arc<DashMap<String, u64>>,
    config: RateLimitConfig,
}

impl RateLimit {
    pub fn new(config: RateLimitConfig) -> Self {
        Self {
            records: Arc::new(DashMap::new()),
            blacklist: Arc::new(DashMap::new()),
            config,
        }
    }

    /// 只检查黑名单（不计数）：供"已封禁则跳过昂贵校验"的路径使用
    pub fn is_blacklisted(&self, ip: &str) -> bool {
        if let Some(entry) = self.blacklist.get(ip) {
            if *entry.value() > current_millis() {
                return true;
            }
            // 已过期：惰性清理
            drop(entry);
            self.blacklist.remove(ip);
        }
        false
    }

    /// 记录一次访问；返回 `true` 表示允许，`false` 表示被限流/黑名单。
    pub fn record(&self, ip: &str) -> bool {
        if self.is_blacklisted(ip) {
            return false;
        }
        let now = current_millis();

        let rate_ms = self.config.rate_time.as_millis() as u64;
        let max = self.config.max_requests;

        // 累计/新建计数
        let mut exceeded = false;
        {
            let mut entry = self.records.entry(ip.to_string()).or_insert(RateRecord {
                time_ms: now,
                count: 0,
            });
            if now.saturating_sub(entry.time_ms) < rate_ms {
                entry.count = entry.count.saturating_add(1);
                if entry.count >= max {
                    entry.count = 0;
                    exceeded = true;
                }
            } else {
                // 超出周期，重置
                entry.time_ms = now;
                entry.count = 1;
            }
        }

        if exceeded {
            let expiry = now + self.config.black_time.as_millis() as u64;
            self.records.remove(ip);
            self.blacklist.insert(ip.to_string(), expiry);
            return false;
        }

        true
    }

    /// 返回当前配置（用于启动日志）
    pub fn config(&self) -> RateLimitConfig {
        self.config
    }
}

fn current_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allow_under_limit() {
        let rl = RateLimit::new(RateLimitConfig {
            max_requests: 3,
            rate_time: Duration::from_secs(60),
            black_time: Duration::from_secs(600),
        });
        assert!(rl.record("1.1.1.1"));
        assert!(rl.record("1.1.1.1"));
        assert!(!rl.record("1.1.1.1")); // 第 3 次触发黑名单
        assert!(!rl.record("1.1.1.1")); // 已被封禁
        assert!(rl.record("2.2.2.2")); // 其他 IP 不受影响
    }

    #[test]
    fn window_resets_after_rate_time() {
        let rl = RateLimit::new(RateLimitConfig {
            max_requests: 2,
            rate_time: Duration::from_millis(20),
            black_time: Duration::from_secs(600),
        });
        assert!(rl.record("3.3.3.3"));
        std::thread::sleep(Duration::from_millis(40));
        // 窗口已过期，计数重置，不应触发封禁
        assert!(rl.record("3.3.3.3"));
    }

    #[test]
    fn is_blacklisted_does_not_count() {
        let rl = RateLimit::new(RateLimitConfig {
            max_requests: 2,
            rate_time: Duration::from_secs(60),
            black_time: Duration::from_secs(600),
        });
        assert!(!rl.is_blacklisted("5.5.5.5"));
        assert!(rl.record("5.5.5.5"));
        // 只查询不应消耗配额
        assert!(!rl.is_blacklisted("5.5.5.5"));
        assert!(!rl.is_blacklisted("5.5.5.5"));
        // 第 2 次达到上限并封禁
        assert!(!rl.record("5.5.5.5"));
        assert!(rl.is_blacklisted("5.5.5.5"));
        assert!(!rl.record("5.5.5.5"));
        assert!(rl.is_blacklisted("5.5.5.5"));
        assert!(!rl.is_blacklisted("6.6.6.6"));
    }

    #[test]
    fn blacklist_expires_lazily() {
        let rl = RateLimit::new(RateLimitConfig {
            max_requests: 2,
            rate_time: Duration::from_secs(60),
            black_time: Duration::from_millis(10),
        });
        assert!(rl.record("4.4.4.4")); // 第 1 次放行
        assert!(!rl.record("4.4.4.4")); // 第 2 次触发封禁
        assert!(!rl.record("4.4.4.4")); // 封禁期内
        std::thread::sleep(Duration::from_millis(30));
        assert!(rl.record("4.4.4.4")); // 封禁过期后放行
    }
}
