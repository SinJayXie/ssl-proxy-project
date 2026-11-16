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
            .ok_or_else(|| format!("TUN 直连 DNS 查询失败: {domain}"));
    }

    let mut cache = state.dns_cache.write().await;
    if let Some(ip) = cache.get(domain) {
        return Ok(ip.clone());
    }

    match state.dns_resolver.lookup_ip(domain).await {
        Ok(lookup) => {
            if let Some(ip) = lookup.iter().next() {
                let ip_str = ip.to_string();
                cache.insert(domain.to_string(), ip_str.clone());
                Ok(ip_str)
            } else {
                Err("No IP found".to_string())
            }
        }
        Err(e) => Err(e.to_string()),
    }
}
