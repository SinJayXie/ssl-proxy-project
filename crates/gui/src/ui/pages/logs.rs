use crate::core::Core;
use crate::ui::assets::mdi;
use crate::ui::{i18n, theme};
use gpui_kit::base::{h_flex, v_flex};
use gpui_kit::component::button::{Button, ButtonVariants as _};
use gpui_kit::component::scroll::ScrollableElement;
use gpui_kit::component::{ActiveTheme as _, Icon, Sizable as _};
use gpui_kit::*;
use once_cell::sync::Lazy;
use regex::Regex;
use std::sync::Arc;

static LOG_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"^\[(\S+)\s+(INFO|WARN|ERROR|DEBUG)\]\s*(.*)$").expect("valid log regex")
});

struct LogEntry {
    time: String,
    level: String,
    message: String,
}

pub struct LogsPage {
    core: Arc<Core>,
    entries: Vec<LogEntry>,
    scroll: ScrollHandle,
}

impl LogsPage {
    pub fn new(core: Arc<Core>, cx: &mut Context<Self>) -> Self {
        let mut page = Self {
            core,
            entries: Vec::new(),
            scroll: ScrollHandle::new(),
        };
        page.refresh(cx);
        page
    }

    fn refresh(&mut self, cx: &mut Context<Self>) {
        let raw = self.core.read_logs();
        self.entries = raw
            .lines()
            .map(|line| {
                if let Some(captures) = LOG_RE.captures(line) {
                    LogEntry {
                        time: captures[1].to_string(),
                        level: captures[2].to_string(),
                        message: captures[3].to_string(),
                    }
                } else {
                    LogEntry {
                        time: String::new(),
                        level: "INFO".to_string(),
                        message: line.to_string(),
                    }
                }
            })
            .collect();

        self.scroll.scroll_to_bottom();
        cx.notify();
    }

    fn level_color(level: &str) -> Hsla {
        match level {
            "WARN" => theme::log_warn(),
            "ERROR" => theme::log_error(),
            "DEBUG" => theme::log_debug(),
            _ => theme::log_info(),
        }
    }
}

impl Render for LogsPage {
    fn render(&mut self, _: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let mut list = v_flex().gap_1();

        if self.entries.is_empty() {
            list = list.child(
                v_flex()
                    .items_center()
                    .justify_center()
                    .py_8()
                    .gap_2()
                    .child(
                        Icon::default().path(mdi("text-box-outline"))
                            .size_8()
                            .text_color(theme::text_muted(cx)),
                    )
                    .child(
                        div()
                            .text_sm()
                            .text_color(theme::text_muted(cx))
                            .child(i18n::t("NO_MATCH")),
                    ),
            );
        } else {
            let mut body = v_flex().gap_1();
            let row_hover = cx.theme().secondary_hover;
            for (index, entry) in self.entries.iter().enumerate() {
                let color = Self::level_color(&entry.level);
                let line = if entry.time.is_empty() {
                    format!("[{}] {}", entry.level, entry.message)
                } else {
                    format!("[{} {}] {}", entry.time, entry.level, entry.message)
                };

                body = body.child(
                    h_flex()
                        .id(ElementId::Name(format!("log-{index}").into()))
                        .items_start()
                        .gap_2()
                        .px_2()
                        .py_1()
                        .rounded(px(4.))
                        .cursor_pointer()
                        .hover(move |style| style.bg(row_hover))
                        .child(
                            div()
                                .w(px(3.))
                                .self_stretch()
                                .flex_shrink_0()
                                .bg(color),
                        )
                        .child(
                            div()
                                .w(px(150.))
                                .text_xs()
                                .font_family("Consolas")
                                .text_color(theme::text_muted(cx))
                                .child(entry.time.clone()),
                        )
                        .child(
                            div()
                                .w(px(50.))
                                .text_xs()
                                .font_family("Consolas")
                                .text_color(color)
                                .child(entry.level.clone()),
                        )
                        .child(
                            div()
                                .flex_1()
                                .text_xs()
                                .font_family("Consolas")
                                .child(entry.message.clone()),
                        )
                        .on_click(move |_, _, cx| {
                            cx.write_to_clipboard(ClipboardItem::new_string(line.clone()));
                        }),
                );
            }
            list = list.child(body);
        }

        v_flex()
            .size_full()
            .gap_4()
            .child(
                h_flex()
                    .items_center()
                    .justify_between()
                    .pr_6()
                    .child(
                        div()
                            .text_size(px(20.))
                            .font_weight(FontWeight::SEMIBOLD)
                            .child(i18n::t("LOG")),
                    )
                    .child(
                        Button::new("logs-refresh")
                            .ghost()
                            .small()
                            .icon(Icon::default().path(mdi("refresh")))
                            .label("Refresh")
                            .on_click(cx.listener(|this, _, _, cx| this.refresh(cx))),
                    ),
            )
            .child(
                div()
                    .id("logs-scroll")
                    .flex_1()
                    .min_h_0()
                    .pr_6()
                    .track_scroll(&self.scroll)
                    .overflow_y_scrollbar()
                    .child(list),
            )
    }
}
