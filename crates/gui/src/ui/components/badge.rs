use crate::ui::{i18n, theme};
use gpui_kit::base::h_flex;
use gpui_kit::component::ActiveTheme as _;
use gpui_kit::*;

/// PROXY / DIRECT badge matching the Vue `.badge` styles.
///
/// UDP sessions carry their transport in [`protocol_badge`]; here only the
/// route matters, so `UDP-PROXY` maps to PROXY and plain `UDP` to DIRECT.
pub fn mode_badge(mode: &str, cx: &App) -> AnyElement {
    let upper = mode.to_ascii_uppercase();
    let is_proxy = upper == "PROXY" || upper == "UDP-PROXY";
    let label = i18n::t(if is_proxy { "PROXY" } else { "DIRECT" });
    badge(label, is_proxy, cx)
}

/// Transport pill: `TCP` for regular connections, `UDP` for relay sessions.
pub fn protocol_badge(mode: &str, cx: &App) -> AnyElement {
    let is_udp = mode.to_ascii_uppercase().starts_with("UDP");
    let (bg, fg) = if is_udp {
        (cx.theme().warning.opacity(0.16), cx.theme().warning)
    } else {
        (theme::bg_tertiary(cx), theme::text_secondary(cx))
    };

    h_flex()
        .gap(px(3.))
        .px(px(4.))
        .py(px(2.))
        .rounded(px(10.))
        .bg(bg)
        .text_size(px(10.))
        .font_weight(FontWeight::MEDIUM)
        .text_color(fg)
        .child(i18n::t(if is_udp { "UDP_BADGE" } else { "TCP_BADGE" }))
        .into_any_element()
}

/// Mode badge with a `MODE_*` i18n label (used by Test Rule).
pub fn test_mode_badge(mode: &str, cx: &App) -> AnyElement {
    let is_proxy = mode.eq_ignore_ascii_case("PROXY");
    let is_direct = mode.eq_ignore_ascii_case("DIRECT");
    let label = i18n::t(&format!("MODE_{mode}"));

    if is_proxy || is_direct {
        return badge(label, is_proxy, cx);
    }

    h_flex()
        .px(px(4.))
        .py(px(2.))
        .rounded(px(10.))
        .text_size(px(11.))
        .font_weight(FontWeight::MEDIUM)
        .text_color(cx.theme().danger)
        .child(label)
        .into_any_element()
}

pub fn badge(label: String, proxy: bool, cx: &App) -> AnyElement {
    let (bg, fg) = if proxy {
        (cx.theme().primary.opacity(0.14), cx.theme().primary)
    } else {
        (cx.theme().success.opacity(0.16), cx.theme().success)
    };

    h_flex()
        .gap(px(3.))
        .px(px(4.))
        .py(px(2.))
        .rounded(px(10.))
        .bg(bg)
        .text_size(px(11.))
        .font_weight(FontWeight::MEDIUM)
        .text_color(fg)
        .child(label)
        .into_any_element()
}

/// Accent pill used next to page titles.
pub fn title_count(count: usize, cx: &App) -> AnyElement {
    div()
        .px(px(7.))
        .py(px(1.))
        .rounded(px(10.))
        .bg(cx.theme().primary)
        .text_color(rgb(0xffffff))
        .text_size(px(11.))
        .font_weight(FontWeight::SEMIBOLD)
        .child(count.to_string())
        .into_any_element()
}

/// Muted pill used in rule group headers.
pub fn group_count(count: usize, cx: &App) -> AnyElement {
    div()
        .px(px(6.))
        .rounded(px(10.))
        .bg(theme::bg_tertiary(cx))
        .text_color(theme::text_muted(cx))
        .text_size(px(11.))
        .font_weight(FontWeight::MEDIUM)
        .child(count.to_string())
        .into_any_element()
}

/// Small count pill used in connection group meta rows.
pub fn conn_count(count: usize, cx: &App) -> AnyElement {
    div()
        .px(px(5.))
        .rounded(px(8.))
        .bg(theme::bg_active(cx))
        .text_color(cx.theme().primary)
        .text_size(px(11.))
        .font_weight(FontWeight::MEDIUM)
        .child(count.to_string())
        .into_any_element()
}
