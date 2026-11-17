use crate::ui::assets::mdi;
use crate::ui::{i18n, theme};
use gpui_kit::base::{h_flex, v_flex};
use gpui_kit::component::WindowExt as _;
use gpui_kit::component::button::Button;
use gpui_kit::component::scroll::ScrollableElement;
use gpui_kit::component::{ActiveTheme as _, Icon};
use gpui_kit::*;
use std::sync::OnceLock;

/// 第三方组件清单（`cargo metadata` 生成，编译期嵌入）。
#[derive(serde::Deserialize)]
struct NoticeEntry {
    name: String,
    version: String,
    license: String,
}

fn notices() -> &'static [NoticeEntry] {
    static NOTICES: OnceLock<Vec<NoticeEntry>> = OnceLock::new();
    NOTICES.get_or_init(|| {
        serde_json::from_str(include_str!("../../../assets/third-party-notices.json"))
            .unwrap_or_default()
    })
}

fn open_notices(window: &mut Window, cx: &mut App) {
    window.open_dialog(cx, move |dialog, _, cx| {
        let entries = notices();
        let muted = theme::text_muted(cx);
        let border = theme::border_light(cx);

        let header = h_flex()
            .w_full()
            .items_center()
            .gap_2()
            .pb_1()
            .border_b_1()
            .border_color(border)
            .text_xs()
            .font_weight(FontWeight::SEMIBOLD)
            .child(div().flex_1().child(i18n::t("THIRD_PARTY_NAME")))
            .child(
                div()
                    .w(px(64.))
                    .flex_shrink_0()
                    .child(i18n::t("THIRD_PARTY_VERSION")),
            )
            .child(
                div()
                    .w(px(190.))
                    .flex_shrink_0()
                    .child(i18n::t("THIRD_PARTY_LICENSE")),
            );

        let rows = entries.iter().map(|entry| {
            h_flex()
                .w_full()
                .items_center()
                .gap_2()
                .py(px(3.))
                .border_b_1()
                .border_color(border)
                .text_xs()
                .child(
                    div()
                        .flex_1()
                        .min_w_0()
                        .overflow_hidden()
                        .child(entry.name.clone()),
                )
                .child(
                    div()
                        .w(px(64.))
                        .flex_shrink_0()
                        .text_color(muted)
                        .child(entry.version.clone()),
                )
                .child(
                    div()
                        .w(px(190.))
                        .flex_shrink_0()
                        .text_color(muted)
                        .child(entry.license.clone()),
                )
        });

        dialog
            .w(px(560.))
            .bg(theme::dialog(cx))
            .title(i18n::t("THIRD_PARTY_TITLE"))
            .child(
                v_flex()
                    .gap_2()
                    .child(
                        div()
                            .text_xs()
                            .text_color(muted)
                            .child(i18n::t("THIRD_PARTY_DESC")),
                    )
                    .child(
                        div().text_xs().text_color(muted).child(i18n::t_with(
                            "THIRD_PARTY_COUNT",
                            &[("n", &entries.len().to_string())],
                        )),
                    )
                    .child(
                        div()
                            .text_xs()
                            .text_color(muted)
                            .child(i18n::t("THIRD_PARTY_FULL_HINT")),
                    )
                    .child(
                        div()
                            .id("third-party-scroll")
                            .max_h(px(420.))
                            .pr_2()
                            .overflow_y_scrollbar()
                            .child(v_flex().w_full().child(header).children(rows)),
                    ),
            )
            .footer(
                h_flex().w_full().justify_end().child(
                    Button::new("third-party-close")
                        .label(i18n::t("CLOSE"))
                        .on_click(|_, window, cx| window.close_dialog(cx)),
                ),
            )
    });
}

pub struct AboutPage;

impl AboutPage {
    pub fn new() -> Self {
        Self
    }
}

impl Render for AboutPage {
    fn render(&mut self, _: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let version = env!("CARGO_PKG_VERSION");
        let year = 2026;
        let pill_hover = cx.theme().secondary_hover;

        v_flex()
            .size_full()
            .items_center()
            .pr_6()
            .gap_3()
            .pt_8()
            .child(
                Icon::default().path(mdi("proxy-outline"))
                    .size_16()
                    .text_color(cx.theme().primary),
            )
            .child(
                div()
                    .text_2xl()
                    .font_weight(FontWeight::BOLD)
                    .child("SSL Proxy Client"),
            )
            .child(
                div()
                    .px_2()
                    .rounded(px(10.))
                    .bg(cx.theme().primary.opacity(0.12))
                    .text_color(cx.theme().primary)
                    .text_xs()
                    .child(format!("v{version}")),
            )
            .child(
                div()
                    .max_w(px(420.))
                    .text_sm()
                    .text_color(theme::text_muted(cx))
                    .child(i18n::t("ABOUT_DESC")),
            )
            .child(
                h_flex()
                    .items_center()
                    .gap_2()
                    .child(
                        div()
                            .px_3()
                            .py_1()
                            .rounded(px(20.))
                            .border_1()
                            .border_color(cx.theme().border)
                            .text_xs()
                            .text_color(theme::text_muted(cx))
                            .child("MIT License"),
                    )
                    .child(
                        div()
                            .id("open-third-party-notices")
                            .px_3()
                            .py_1()
                            .rounded(px(20.))
                            .border_1()
                            .border_color(cx.theme().border)
                            .text_xs()
                            .text_color(theme::text_muted(cx))
                            .cursor_pointer()
                            .hover(move |style| style.bg(pill_hover))
                            .on_click(cx.listener(|_, _, window, cx| open_notices(window, cx)))
                            .child(i18n::t("THIRD_PARTY_BUTTON")),
                    ),
            )
            .child(
                v_flex()
                    .max_w(px(480.))
                    .gap_1()
                    .p_4()
                    .rounded(px(10.))
                    .bg(theme::card(cx))
                    .border_1()
                    .border_color(theme::border_light(cx))
                    .shadow_xs()
                    .child(
                        div()
                            .text_sm()
                            .font_weight(FontWeight::SEMIBOLD)
                            .child(i18n::t("DISCLAIMER_TITLE")),
                    )
                    .child(
                        div()
                            .id("about-disclaimer-scroll")
                            .max_h(px(160.))
                            .pr_4()
                            .overflow_y_scrollbar()
                            .text_xs()
                            .text_color(theme::text_muted(cx))
                            .child(i18n::t("DISCLAIMER_TEXT")),
                    ),
            )
            .child(
                div()
                    .text_xs()
                    .text_color(theme::text_muted(cx))
                    .child(format!("© {year} SSL Proxy Team")),
            )
    }
}
