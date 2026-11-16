//! 统一路由决策：TCP / UDP / 未来 TUN 数据面共用同一套分流语义。
//!
//! 这是 mihomo「规则 → DIRECT/PROXY 出站」不变量在本项目的落地点：
//! - `Outbound::Direct` 的流量必须用物理网卡原生 socket，绝不进入 TLS 隧道；
//! - `Outbound::Proxy` 的流量才进入私有协议隧道，绝不能落到物理网卡明文直出；
//! - DNS 失败时不得按真实 IP 直连（会把域名规则降级成 IP 规则），
//!   有上游则交给服务端解析，无上游则拒绝。
//!
//! 决策本身是纯函数，不依赖 I/O 或 `AppState`，便于 TUN 数据面复用与单元测试。

use crate::types::RuleConfig;

use super::connect::match_rules;

/// 出站类型。与具体 socket 生命周期解耦，TUN 数据面据此选择
/// 物理网卡原生连接（DirectConnector）或 TLS 隧道（TunnelConnector）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outbound {
    /// 直连：物理网卡原生 socket，不进入任何隧道。
    Direct,
    /// 代理：进入 TLS 私有协议隧道。
    Proxy,
    /// 拒绝：无可用出口（如无上游且 DNS 解析失败）。
    Reject,
}

/// 决策依据，用于日志与 UI 展示，不参与分流判定本身。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecisionReason {
    /// 未配置上游代理，强制直连。
    NoUpstream,
    /// UDP `off`/`direct` 模式强制直连（忽略规则）。
    ForcedDirect,
    /// HOST/GEO 规则命中。
    MatchedRule,
    /// 目标地区为私网（PRIVATE），直连。
    PrivateNetwork,
    /// 目标地区在 `directs` 名单中，直连。
    DirectsRegion,
    /// 无规则命中且无地区例外，默认走代理。
    DefaultProxy,
    /// DNS 解析失败且无上游，拒绝。
    DnsFailed,
    /// 目标无解析结果，禁止按 IP 直连，改走代理交给服务端解析。
    NoResolvedIp,
}

/// 结构化路由决策，替代散落在各处的 `is_direct: bool` / `"PROXY"` 字符串。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteDecision {
    pub outbound: Outbound,
    pub reason: DecisionReason,
    /// 解析出的目标 IP；代理路径允许为空（域名交给服务端解析）。
    pub resolved_ip: Option<String>,
}

impl RouteDecision {
    pub fn is_direct(&self) -> bool {
        self.outbound == Outbound::Direct
    }

    /// 供 TUN 数据面判定是否应进入隧道（设备层接入后使用）。
    #[allow(dead_code)]
    pub fn is_proxy(&self) -> bool {
        self.outbound == Outbound::Proxy
    }
}

/// 纯决策输入。`rule_mode` 为 `match_rules` 的结果；`force_direct` 供
/// UDP `off`/`direct` 模式使用（TCP 恒为 false）。
pub struct RouteInput<'a> {
    pub has_upstream: bool,
    pub rule_mode: Option<&'a str>,
    pub geo_code: &'a str,
    pub directs: &'a [String],
    pub resolved_ip: Option<&'a str>,
    pub force_direct: bool,
}

/// 统一分流判定。语义与改动前的 TCP `resolve_and_connect` /
/// UDP `decide_udp_route` 保持一致，只是集中到一处并可测试。
///
/// 优先级：
/// 1. 强制直连（UDP off/direct）→ Direct；
/// 2. 无上游 → Direct（解析失败则 Reject）；
/// 3. 规则命中 → `DIRECT` 且已解析则 Direct，否则 Proxy（解析失败不按 IP 直连）；
/// 4. 无规则命中 → 有解析且命中 PRIVATE/directs 则 Direct，否则 Proxy。
pub fn classify(input: &RouteInput<'_>) -> RouteDecision {
    let RouteInput {
        has_upstream,
        rule_mode,
        geo_code,
        directs,
        resolved_ip,
        force_direct,
    } = input;

    if *force_direct {
        return RouteDecision {
            outbound: Outbound::Direct,
            reason: DecisionReason::ForcedDirect,
            resolved_ip: resolved_ip.map(|s| s.to_string()),
        };
    }

    if !*has_upstream {
        let outbound = if resolved_ip.is_some() {
            Outbound::Direct
        } else {
            Outbound::Reject
        };
        let reason = if resolved_ip.is_some() {
            DecisionReason::NoUpstream
        } else {
            DecisionReason::DnsFailed
        };
        return RouteDecision {
            outbound,
            reason,
            resolved_ip: resolved_ip.map(|s| s.to_string()),
        };
    }

    if let Some(mode) = rule_mode {
        if mode.eq_ignore_ascii_case("DIRECT") && resolved_ip.is_some() {
            return RouteDecision {
                outbound: Outbound::Direct,
                reason: DecisionReason::MatchedRule,
                resolved_ip: resolved_ip.map(|s| s.to_string()),
            };
        }
        // 规则要求 DIRECT 但无解析结果：不得按 IP 直连（域名规则失效），
        // 也不得落到物理网卡，统一交给代理（可用性 + 防泄漏优先）。
        return RouteDecision {
            outbound: Outbound::Proxy,
            reason: if mode.eq_ignore_ascii_case("DIRECT") {
                DecisionReason::NoResolvedIp
            } else {
                DecisionReason::MatchedRule
            },
            resolved_ip: resolved_ip.map(|s| s.to_string()),
        };
    }

    let region_direct = resolved_ip.is_some()
        && (geo_code.eq_ignore_ascii_case("PRIVATE")
            || directs.iter().any(|d| d.eq_ignore_ascii_case(geo_code)));

    if region_direct {
        let reason = if geo_code.eq_ignore_ascii_case("PRIVATE") {
            DecisionReason::PrivateNetwork
        } else {
            DecisionReason::DirectsRegion
        };
        return RouteDecision {
            outbound: Outbound::Direct,
            reason,
            resolved_ip: resolved_ip.map(|s| s.to_string()),
        };
    }

    RouteDecision {
        outbound: Outbound::Proxy,
        reason: DecisionReason::DefaultProxy,
        resolved_ip: resolved_ip.map(|s| s.to_string()),
    }
}

/// 便捷封装：基于规则列表分类（TUN 数据面拿到 host/geo 后可直接调用）。
#[allow(dead_code)]
pub fn classify_with_rules(
    has_upstream: bool,
    host: &str,
    geo_code: &str,
    rules: &[RuleConfig],
    directs: &[String],
    resolved_ip: Option<&str>,
    force_direct: bool,
) -> RouteDecision {
    let rule_mode = match_rules(host, geo_code, rules);
    classify(&RouteInput {
        has_upstream,
        rule_mode: rule_mode.as_deref(),
        geo_code,
        directs,
        resolved_ip,
        force_direct,
    })
}

/// 不变量断言：DIRECT 决策绝不携带代理出站标记；PROXY 决策允许无解析 IP。
/// TUN 数据面在创建出站 socket 前应调用此函数做防御性校验。
#[allow(dead_code)]
pub fn assert_safe_decision(decision: &RouteDecision) -> Result<(), &'static str> {
    match decision.outbound {
        Outbound::Direct if decision.resolved_ip.is_none() => {
            Err("DIRECT decision without resolved IP")
        }
        Outbound::Direct | Outbound::Proxy | Outbound::Reject => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dirs(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    fn decide(
        has_upstream: bool,
        rule_mode: Option<&str>,
        geo: &str,
        directs: &[String],
        resolved: Option<&str>,
        force_direct: bool,
    ) -> RouteDecision {
        classify(&RouteInput {
            has_upstream,
            rule_mode,
            geo_code: geo,
            directs,
            resolved_ip: resolved,
            force_direct,
        })
    }

    #[test]
    fn no_upstream_with_ip_goes_direct() {
        let d = decide(
            false,
            Some("PROXY"),
            "US",
            &dirs(&[]),
            Some("1.2.3.4"),
            false,
        );
        assert_eq!(d.outbound, Outbound::Direct);
        assert_eq!(d.reason, DecisionReason::NoUpstream);
        assert!(assert_safe_decision(&d).is_ok());
    }

    #[test]
    fn no_upstream_without_ip_is_rejected() {
        // DNS 失败且无上游：不能直连（无 IP），也不能代理（无隧道）→ 拒绝。
        let d = decide(false, None, "UNK", &dirs(&[]), None, false);
        assert_eq!(d.outbound, Outbound::Reject);
        assert_eq!(d.reason, DecisionReason::DnsFailed);
    }

    #[test]
    fn forced_direct_ignores_proxy_rule() {
        // UDP off/direct 模式：即便规则命中 PROXY 也强制直连。
        let d = decide(true, Some("PROXY"), "US", &dirs(&[]), Some("1.2.3.4"), true);
        assert_eq!(d.outbound, Outbound::Direct);
        assert_eq!(d.reason, DecisionReason::ForcedDirect);
    }

    #[test]
    fn host_rule_direct_wins_with_resolved_ip() {
        let d = decide(
            true,
            Some("DIRECT"),
            "CN",
            &dirs(&[]),
            Some("1.2.3.4"),
            false,
        );
        assert_eq!(d.outbound, Outbound::Direct);
        assert_eq!(d.reason, DecisionReason::MatchedRule);
    }

    #[test]
    fn host_rule_direct_without_ip_falls_back_to_proxy() {
        // 安全不变量：解析失败时禁止按 IP 直连，域名规则必须交给服务端解析。
        let d = decide(true, Some("DIRECT"), "CN", &dirs(&[]), None, false);
        assert_eq!(d.outbound, Outbound::Proxy);
        assert_eq!(d.reason, DecisionReason::NoResolvedIp);
        assert!(d.resolved_ip.is_none(), "代理路径允许无解析 IP");
    }

    #[test]
    fn proxy_rule_always_goes_proxy_even_with_ip() {
        let d = decide(
            true,
            Some("PROXY"),
            "US",
            &dirs(&[]),
            Some("1.2.3.4"),
            false,
        );
        assert_eq!(d.outbound, Outbound::Proxy);
    }

    #[test]
    fn private_geo_falls_back_to_direct() {
        let d = decide(
            true,
            None,
            "PRIVATE",
            &dirs(&[]),
            Some("192.168.1.10"),
            false,
        );
        assert_eq!(d.outbound, Outbound::Direct);
        assert_eq!(d.reason, DecisionReason::PrivateNetwork);
    }

    #[test]
    fn directs_region_is_case_insensitive() {
        let d = decide(true, None, "cn", &dirs(&["CN"]), Some("1.2.3.4"), false);
        assert_eq!(d.outbound, Outbound::Direct);
        assert_eq!(d.reason, DecisionReason::DirectsRegion);
    }

    #[test]
    fn unknown_geo_without_rule_goes_proxy() {
        let d = decide(true, None, "US", &dirs(&["CN"]), Some("1.2.3.4"), false);
        assert_eq!(d.outbound, Outbound::Proxy);
        assert_eq!(d.reason, DecisionReason::DefaultProxy);
    }

    #[test]
    fn direct_without_ip_fails_assertion() {
        let d = RouteDecision {
            outbound: Outbound::Direct,
            reason: DecisionReason::MatchedRule,
            resolved_ip: None,
        };
        assert!(assert_safe_decision(&d).is_err());
    }
}
