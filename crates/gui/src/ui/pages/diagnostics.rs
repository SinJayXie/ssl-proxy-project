use crate::core::diagnostics::{format_report, CheckResult, CheckStatus};
use crate::core::Core;
use crate::ui::assets::mdi;
use crate::ui::{i18n, theme};
use gpui_kit::base::{h_flex, v_flex};
use gpui_kit::component::button::{Button, ButtonVariants as _};
use gpui_kit::component::scroll::ScrollableElement;
use gpui_kit::component::{ActiveTheme as _, Disableable as _, Icon};
use gpui_kit::*;
use std::sync::Arc;
use std::time::Duration;

pub struct DiagnosticsPage {
    core: Arc<Core>,
    results: Vec<CheckResult>,
    running: bool,
    copied: bool,
    notice: Option<String>,
    _task: Option<Task<()>>,
}

impl DiagnosticsPage {
    pub fn new(core: Arc<Core>) -> Self {
        Self {
            core,
            results: Vec::new(),
            running: false,
            copied: false,
            notice: None,
            _task: None,
        }
    }

    /// 后台运行五项检查；完成后写回结果并刷新界面。
    fn run(&mut self, cx: &mut Context<Self>) {
        if self.running {
            return;
        }

        self.running = true;
        self.copied = false;
        self.notice = None;
        cx.notify();

        let handle = self.core.run_diagnostics();
        self._task = Some(cx.spawn(async move |this, cx| {
            let results = handle.await.unwrap_or_default();
            let _ = this.update(cx, |page, cx| {
                page.results = results;
                page.running = false;
                cx.notify();
            });
        }));
    }

    /// 复制纯文本报告，并在 1.5 秒后复位复制反馈。
    fn copy(&mut self, cx: &mut Context<Self>) {
        if self.results.is_empty() {
            return;
        }

        cx.write_to_clipboard(ClipboardItem::new_string(format_report(&self.results)));
        self.copied = true;
        self.notice = Some(i18n::t("DIAG_COPIED"));
        cx.notify();

        cx.spawn(async move |this, cx| {
            smol::Timer::after(Duration::from_millis(1500)).await;
            let _ = this.update(cx, |page, cx| {
                page.copied = false;
                page.notice = None;
                cx.notify();
            });
        })
        .detach();
    }

    fn status_key(status: CheckStatus) -> &'static str {
        match status {
            CheckStatus::Pass => "DIAG_STATUS_PASS",
            CheckStatus::Warn => "DIAG_STATUS_WARN",
            CheckStatus::Fail => "DIAG_STATUS_FAIL",
            CheckStatus::Info => "DIAG_STATUS_INFO",
        }
    }

    fn status_color(status: CheckStatus, cx: &App) -> Hsla {
        match status {
            CheckStatus::Pass => cx.theme().success,
            CheckStatus::Warn => cx.theme().warning,
            CheckStatus::Fail => cx.theme().danger,
            CheckStatus::Info => theme::text_muted(cx),
        }
    }
}

impl Render for DiagnosticsPage {
    fn render(&mut self, _: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let muted = theme::text_muted(cx);

        let mut actions = h_flex().items_center().gap_2();
        if self.copied {
            if let Some(notice) = &self.notice {
                actions = actions.child(
                    div()
                        .text_xs()
                        .text_color(cx.theme().success)
                        .child(notice.clone()),
                );
            }
        }
        actions = actions
            .child(
                Button::new("diag-run")
                    .primary()
                    .label(if self.running {
                        i18n::t("DIAG_RUNNING")
                    } else {
                        i18n::t("DIAG_RUN")
                    })
                    .icon(Icon::default().path(mdi(if self.running {
                        "loading"
                    } else {
                        "shield-alert-outline"
                    })))
                    .disabled(self.running)
                    .on_click(cx.listener(|this, _, _, cx| this.run(cx))),
            )
            .child(
                Button::new("diag-copy")
                    .ghost()
                    .label(i18n::t("DIAG_COPY"))
                    .icon(Icon::default().path(mdi(if self.copied {
                        "check"
                    } else {
                        "file-document-outline"
                    })))
                    .disabled(self.results.is_empty() || self.running)
                    .on_click(cx.listener(|this, _, _, cx| this.copy(cx))),
            );

        let header = h_flex()
            .items_start()
            .justify_between()
            .gap_4()
            .pr_6()
            .child(
                v_flex()
                    .gap_1()
                    .child(
                        div()
                            .text_size(px(20.))
                            .font_weight(FontWeight::SEMIBOLD)
                            .child(i18n::t("DIAG_TITLE")),
                    )
                    .child(
                        div()
                            .text_sm()
                            .text_color(muted)
                            .child(i18n::t("DIAG_DESC")),
                    ),
            )
            .child(actions);

        let body: AnyElement = if self.results.is_empty() {
            v_flex()
                .flex_1()
                .items_center()
                .justify_center()
                .gap_2()
                .py_8()
                .child(
                    Icon::default()
                        .path(mdi("shield-alert-outline"))
                        .size_8()
                        .text_color(muted),
                )
                .child(
                    div()
                        .text_sm()
                        .text_color(muted)
                        .child(i18n::t(if self.running {
                            "DIAG_RUNNING"
                        } else {
                            "DIAG_EMPTY"
                        })),
                )
                .into_any_element()
        } else {
            let mut list = v_flex().gap_2();
            for result in &self.results {
                let color = Self::status_color(result.status, cx);

                list = list.child(
                    v_flex()
                        .gap_1()
                        .px_4()
                        .py_3()
                        .rounded(px(10.))
                        .bg(theme::card(cx))
                        .border_1()
                        .border_color(theme::border_light(cx))
                        .child(
                            h_flex()
                                .items_center()
                                .gap_2()
                                .child(
                                    div()
                                        .text_sm()
                                        .font_weight(FontWeight::MEDIUM)
                                        .child(i18n::t(result.name)),
                                )
                                .child(
                                    div()
                                        .px_2()
                                        .rounded(px(9.))
                                        .bg(color.opacity(0.12))
                                        .text_color(color)
                                        .text_xs()
                                        .child(i18n::t(Self::status_key(result.status))),
                                ),
                        )
                        .child(
                            div()
                                .text_xs()
                                .font_family("Consolas")
                                .text_color(muted)
                                .child(result.detail.clone()),
                        ),
                );
            }

            div()
                .id("diag-scroll")
                .flex_1()
                .min_h_0()
                .pr_6()
                .overflow_y_scrollbar()
                .child(list)
                .into_any_element()
        };

        v_flex()
            .size_full()
            .gap_4()
            .child(header)
            .child(body)
    }
}
