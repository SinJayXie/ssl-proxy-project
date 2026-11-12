use crate::ui::assets::mdi;
use crate::ui::{i18n, theme};
use gpui_kit::base::v_flex;
use gpui_kit::component::scroll::ScrollableElement;
use gpui_kit::component::{ActiveTheme as _, Icon};
use gpui_kit::*;

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
