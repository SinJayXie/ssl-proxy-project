use crate::core::types::TestRuleResult;
use crate::core::Core;
use crate::ui::components::badge;
use crate::ui::components::rule_dialog::{self, RulePrefill};
use crate::ui::pages::RulesPage;
use crate::ui::{i18n, theme};
use gpui_kit::base::{h_flex, v_flex};
use gpui_kit::component::button::{Button, ButtonVariants as _};
use gpui_kit::component::input::{Input, InputState};
use gpui_kit::component::{ActiveTheme as _, Disableable as _, Sizable as _};
use gpui_kit::prelude::FluentBuilder as _;
use gpui_kit::*;
use std::sync::Arc;

pub struct TestRulePage {
    core: Arc<Core>,
    rules: WeakEntity<RulesPage>,
    host: Entity<InputState>,
    result: Option<TestRuleResult>,
    error: Option<String>,
    checking: bool,
    _task: Option<Task<()>>,
}

impl TestRulePage {
    pub fn new(
        core: Arc<Core>,
        rules: WeakEntity<RulesPage>,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) -> Self {
        let host = cx.new(|cx| {
            InputState::new(window, cx).placeholder(i18n::t("TEST_RULE_PLACEHOLDER"))
        });

        Self {
            core,
            rules,
            host,
            result: None,
            error: None,
            checking: false,
            _task: None,
        }
    }

    fn can_test(&self, cx: &App) -> bool {
        !self.checking && !self.host.read(cx).value().trim().is_empty()
    }

    fn run_test(&mut self, cx: &mut Context<Self>) {
        if self.checking {
            return;
        }

        let host = self.host.read(cx).value().trim().to_string();
        if host.is_empty() {
            return;
        }

        self.checking = true;
        self.error = None;
        cx.notify();

        let handle = self.core.test_rule(host);
        self._task = Some(cx.spawn(async move |this, cx| {
            let result = handle.await;
            let _ = this.update(cx, |page, cx| {
                page.checking = false;
                match result {
                    Ok(Ok(result)) => {
                        page.result = Some(result);
                        page.error = None;
                    }
                    Ok(Err(err)) => {
                        page.result = None;
                        page.error = Some(err);
                    }
                    Err(err) => {
                        page.result = None;
                        page.error = Some(err.to_string());
                    }
                }
                cx.notify();
            });
        }));
    }

    fn add_rule(&mut self, geo: bool, window: &mut Window, cx: &mut Context<Self>) {
        let Some(result) = self.result.clone() else {
            return;
        };

        let mode = if result.mode.eq_ignore_ascii_case("DIRECT")
            || result.mode.eq_ignore_ascii_case("PROXY")
        {
            result.mode.clone()
        } else {
            "DIRECT".to_string()
        };

        let prefill = if geo {
            if !is_alpha2(&result.alpha2_code) {
                return;
            }
            RulePrefill::new("GEO", result.alpha2_code.clone(), &mode)
        } else {
            RulePrefill::new("HOST", result.host.clone(), &mode)
        };

        let rules = self.rules.clone();
        let on_done = Arc::new(move |cx: &mut App| {
            let _ = rules.update(cx, |page, cx| page.reload(cx));
        });

        rule_dialog::open_rule_dialog(self.core.clone(), prefill, None, on_done, window, cx);
    }
}

impl Render for TestRulePage {
    fn render(&mut self, _: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let can_test = self.can_test(cx);

        let mut content = v_flex()
            .size_full()
            .pr_6()
            .child(
                div()
                    .text_size(px(20.))
                    .font_weight(FontWeight::SEMIBOLD)
                    .mb_4()
                    .child(i18n::t("TEST_RULE")),
            )
            .child(
                h_flex()
                    .gap_2()
                    .mb_4()
                    .child(div().flex_1().child(Input::new(&self.host)))
                    .child(
                        Button::new("test-run")
                            .primary()
                            .label(if self.checking {
                                "...".to_string()
                            } else {
                                i18n::t("TEST_RULE_BTN")
                            })
                            .disabled(!can_test)
                            .on_click(cx.listener(|this, _, _, cx| this.run_test(cx))),
                    ),
            );

        if let Some(error) = &self.error {
            content = content.child(
                div()
                    .text_size(px(12.))
                    .text_color(cx.theme().danger)
                    .child(error.clone()),
            );
        }

        if let Some(result) = &self.result {
            let is_error = result.mode.eq_ignore_ascii_case("ERROR")
                || result.mode.eq_ignore_ascii_case("DNS_ERROR");
            let is_direct = result.mode.eq_ignore_ascii_case("DIRECT");
            let is_proxy = result.mode.eq_ignore_ascii_case("PROXY");
            let bar_color = if is_error {
                cx.theme().danger
            } else if is_direct {
                cx.theme().success
            } else {
                cx.theme().primary
            };

            let body = v_flex()
                .flex_1()
                .p_4()
                .gap_2()
                .child(result_row(
                    i18n::t("TEST_RESULT_HOST"),
                    result.host.clone(),
                    cx,
                ))
                .child(result_row(
                    i18n::t("TEST_RESULT_IP"),
                    result.resolved_ip.clone(),
                    cx,
                ))
                .child(result_row(
                    i18n::t("TEST_RESULT_DNS"),
                    result.dns_server.clone(),
                    cx,
                ))
                .child(result_row(
                    i18n::t("TEST_RESULT_COUNTRY"),
                    format!("{} ({})", result.country, result.alpha2_code),
                    cx,
                ))
                .child(result_row(
                    i18n::t("TEST_RESULT_RULE"),
                    result.matched_rule.clone(),
                    cx,
                ))
                .child(
                    h_flex()
                        .text_size(px(12.))
                        .text_color(theme::text_secondary(cx))
                        .child(
                            div()
                                .w(px(100.))
                                .flex_shrink_0()
                                .text_color(theme::text_muted(cx))
                                .child(i18n::t("TEST_RESULT_MODE")),
                        )
                        .child(badge::test_mode_badge(&result.mode, cx)),
                )
                .child(result_row(
                    i18n::t("TEST_RESULT_TIME"),
                    format!("{} ms", result.elapsed_ms),
                    cx,
                ))
                .when(is_proxy || is_direct, |this| {
                    this.child(
                        h_flex()
                            .items_center()
                            .gap_3()
                            .pt_2()
                            .border_t_1()
                            .border_color(theme::border_light(cx))
                            .child(
                                div()
                                    .w(px(100.))
                                    .flex_shrink_0()
                                    .text_size(px(12.))
                                    .text_color(theme::text_muted(cx))
                                    .child(i18n::t("ADD_TO_RULES")),
                            )
                            .child(
                                h_flex()
                                    .gap(px(4.))
                                    .child(
                                        Button::new("test-add-host")
                                            .small()
                                            .label(i18n::t("HOST"))
                                            .on_click(cx.listener(|this, _, window, cx| {
                                                this.add_rule(false, window, cx)
                                            })),
                                    )
                                    .when(is_alpha2(&result.alpha2_code), |this| {
                                        this.child(
                                            Button::new("test-add-geo")
                                                .small()
                                                .label(i18n::t("GEO"))
                                                .on_click(cx.listener(
                                                    |this, _, window, cx| {
                                                        this.add_rule(true, window, cx)
                                                    },
                                                )),
                                        )
                                    }),
                            ),
                    )
                });

            content = content.child(
                h_flex()
                    .items_stretch()
                    .rounded(px(10.))
                    .bg(theme::card(cx))
                    .border_1()
                    .border_color(theme::border_light(cx))
                    .shadow_xs()
                    .overflow_hidden()
                    .child(div().w(px(3.)).flex_shrink_0().bg(bar_color))
                    .child(body),
            );
        }

        content
    }
}

fn result_row(label: String, value: String, cx: &App) -> AnyElement {
    h_flex()
        .text_size(px(12.))
        .text_color(theme::text_secondary(cx))
        .child(
            div()
                .w(px(100.))
                .flex_shrink_0()
                .text_color(theme::text_muted(cx))
                .child(label),
        )
        .child(value)
        .into_any_element()
}

fn is_alpha2(value: &str) -> bool {
    value.len() == 2
        && value
            .chars()
            .all(|ch| ch.is_ascii_uppercase())
}
