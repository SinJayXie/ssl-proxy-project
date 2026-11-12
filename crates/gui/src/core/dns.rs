use crate::state::AppState;
use std::sync::Arc;

pub async fn lookup(state: &Arc<AppState>, domain: &str) -> Result<String, String> {
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
