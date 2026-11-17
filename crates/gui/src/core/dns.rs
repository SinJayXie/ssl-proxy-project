use crate::state::AppState;
use std::sync::Arc;

/// TUN 是否正在运行（决定解析是否必须绕开系统解析器）。
fn tun_active(state: &Arc<AppState>) -> bool {
    state
        .tun_dns_bypass
        .read()
        .map(|guard| guard.is_some())
        .unwrap_or(false)
}

pub async fn lookup(state: &Arc<AppState>, domain: &str) -> Result<String, String> {
    // TUN 运行中：本进程发出的 :53 查询会被 TUN 自身劫持并应答成 fake-ip，
    // 若继续用系统解析器，缓存里会塞满 198.18.x，分流决策随之失效。
    // 必须改走绑定物理网卡的直连查询。
    if tun_active(state) {
        return crate::core::tun::outbound::lookup_direct(state, domain)
            .await
            .ok_or_else(|| format!("TUN Direct DNS query failed: {domain}"));
    }

    // 短锁查缓存：绝不持锁跨过解析 await——否则第一个发起解析的连接
    // 会把解析期间所有其他连接的查询堵在写锁上（并发建连被串行化）。
    {
        let cache = state.dns_cache.read().await;
        if let Some(ip) = crate::state::cache_lookup_with_ttl(&cache, domain, crate::state::DNS_CACHE_TTL) {
            return Ok(ip.to_string());
        }
    }

    match state.dns_resolver.lookup_ip(domain).await {
        Ok(lookup) => {
            if let Some(ip) = lookup.iter().next() {
                let ip_str = ip.to_string();
                // 短锁写入：覆盖旧条目（旧条目随 insert 自然过期）
                let mut cache = state.dns_cache.write().await;
                cache.insert(
                    domain.to_string(),
                    crate::state::DnsCacheEntry {
                        ip: ip_str.clone(),
                        cached_at: std::time::Instant::now(),
                    },
                );
                Ok(ip_str)
            } else {
                Err("No IP found".to_string())
            }
        }
        Err(e) => Err(e.to_string()),
    }
}
