use crate::core::types::{CountryCodeItem, RuleConfig};
use crate::core::Core;
use crate::ui::assets::mdi;
use crate::ui::components::icon_button::{danger_icon_button, muted_icon_button};
use crate::ui::components::rule_dialog::{self, RulePrefill};
use crate::ui::components::{badge, confirm};
use crate::ui::{i18n, theme};
use gpui_kit::base::{h_flex, v_flex};
use gpui_kit::component::button::{Button, ButtonVariants as _};
use gpui_kit::component::scroll::ScrollableElement;
use gpui_kit::component::{Icon, Sizable as _};
use gpui_kit::prelude::FluentBuilder as _;
use gpui_kit::*;
use std::sync::Arc;

pub struct RulesPage {
    core: Arc<Core>,
    rules: Vec<RuleConfig>,
    countries: Vec<CountryCodeItem>,
    host_open: bool,
    geo_open: bool,
}

impl RulesPage {
    pub fn new(core: Arc<Core>, cx: &mut Context<Self>) -> Self {
        let rules = core.snapshot_rules().unwrap_or_default();
        let countries = core.geo_countries();
        let _ = cx;
        Self {
            core,
            rules,
            countries,
            host_open: true,
            geo_open: true,
        }
    }

    pub fn reload(&mut self, cx: &mut Context<Self>) {
        if let Some(rules) = self.core.snapshot_rules() {
            if self.rules != rules {
                self.rules = rules;
                cx.notify();
            }
        }
    }

    fn open_editor(
        &mut self,
        editing: Option<usize>,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let prefill = match editing.and_then(|index| self.rules.get(index)) {
            Some(rule) => RulePrefill::from_rule(rule),
            None => RulePrefill::new("HOST", String::new(), "DIRECT"),
        };

        let weak = cx.weak_entity();
        let on_done = Arc::new(move |cx: &mut App| {
            let _ = weak.update(cx, |page, cx| page.reload(cx));
        });

        rule_dialog::open_rule_dialog(self.core.clone(), prefill, editing, on_done, window, cx);
    }

    fn delete_rule(&mut self, index: usize, window: &mut Window, cx: &mut Context<Self>) {
        let weak = cx.weak_entity();
        let core = self.core.clone();

        confirm::open_confirm(
            window,
            cx,
            i18n::t("DELETE_RULE_TITLE"),
            i18n::t("DELETE_RULE_PROMPT"),
            true,
            move |_, cx| {
                let handle = core.delete_rule(index);
                let weak = weak.clone();
                cx.spawn(async move |cx| {
                    let _ = handle.await;
                    let _ = weak.update(cx, |page, cx| page.reload(cx));
                })
                .detach();
            },
        );
    }

    fn section(
        &self,
        title: String,
        open: bool,
        rules: Vec<(usize, RuleConfig)>,
        is_host: bool,
        cx: &mut Context<Self>,
    ) -> AnyElement {
        let weak = cx.weak_entity();
        let header_hover = theme::card_hover(cx);

        let count = rules.len();
        let header = h_flex()
            .id(ElementId::Name(
                format!("rule-group-{}", if is_host { "host" } else { "geo" }).into(),
            ))
            .items_center()
            .justify_between()
            .px_3()
            .py_2()
            .cursor_pointer()
            .hover(move |style| style.bg(header_hover))
            .on_click(move |_, _, cx| {
                let _ = weak.update(cx, |page, cx| {
                    if is_host {
                        page.host_open = !page.host_open;
                    } else {
                        page.geo_open = !page.geo_open;
                    }
                    cx.notify();
                });
            })
            .child(
                h_flex()
                    .items_center()
                    .gap(px(6.))
                    .child(
                        Icon::default()
                            .path(mdi(if is_host { "web" } else { "earth" }))
                            .w(px(16.))
                            .h(px(16.))
                            .text_color(theme::text_muted(cx)),
                    )
                    .child(
                        div()
                            .text_size(px(12.))
                            .font_weight(FontWeight::SEMIBOLD)
                            .child(title),
                    )
                    .child(badge::group_count(count, cx)),
            )
            .child(
                Icon::default()
                    .path(mdi("chevron-down"))
                    .w(px(16.))
                    .h(px(16.))
                    .text_color(theme::text_muted(cx))
                    .rotate(radians(if open { std::f32::consts::PI } else { 0.0 })),
            );

        let mut rows = v_flex();
        if open {
            if rules.is_empty() {
                rows = rows.child(
                    div()
                        .w_full()
                        .p_3()
                        .text_size(px(12.))
                        .text_align(TextAlign::Center)
                        .text_color(theme::text_muted(cx))
                        .child(i18n::t("NO_MATCH")),
                );
            } else {
                let total = rules.len();
                for (position, (index, rule)) in rules.into_iter().enumerate() {
                    rows = rows.child(
                        self.rule_row(index, rule, position + 1 == total, cx),
                    );
                }
            }
        }

        v_flex()
            .rounded(px(10.))
            .bg(theme::card(cx))
            .border_1()
            .border_color(theme::border_light(cx))
            .shadow_xs()
            .overflow_hidden()
            .child(header)
            .when(open, |this| {
                this.child(
                    v_flex()
                        .border_t_1()
                        .border_color(theme::border_light(cx))
                        .child(rows),
                )
            })
            .into_any_element()
    }

    fn rule_row(
        &self,
        index: usize,
        rule: RuleConfig,
        is_last: bool,
        cx: &mut Context<Self>,
    ) -> AnyElement {
        let mode = rule.mode.clone();
        let is_host = rule.rule_type.eq_ignore_ascii_case("HOST");
        let match_str = if is_host {
            rule.match_str.clone()
        } else {
            self.countries
                .iter()
                .find(|country| {
                    country.alpha2_code.eq_ignore_ascii_case(&rule.match_str)
                })
                .map(|country| format!("{} ({})", country.country, rule.match_str))
                .unwrap_or_else(|| rule.match_str.clone())
        };

        let weak_edit = cx.weak_entity();
        let weak_delete = cx.weak_entity();
        let row_hover = theme::card_hover(cx);

        h_flex()
            .items_center()
            .gap_3()
            .px_3()
            .py_2()
            .text_size(px(12.))
            .when(!is_last, |this| {
                this.border_b_1().border_color(theme::border_light(cx))
            })
            .hover(move |style| style.bg(row_hover))
            .child(
                h_flex()
                    .flex_1()
                    .min_w_0()
                    .items_center()
                    .gap(px(6.))
                    .text_color(theme::text_secondary(cx))
                    .child(
                        Icon::default()
                            .path(mdi(if is_host { "regex" } else { "flag-outline" }))
                            .w(px(16.))
                            .h(px(16.))
                            .text_color(theme::text_muted(cx)),
                    )
                    .child(div().min_w_0().overflow_hidden().child(match_str)),
            )
            .child(
                h_flex()
                    .w(px(80.))
                    .flex_shrink_0()
                    .items_center()
                    .gap(px(6.))
                    .child(
                        Icon::default()
                            .path(mdi("file-document-outline"))
                            .w(px(16.))
                            .h(px(16.))
                            .text_color(theme::text_muted(cx)),
                    )
                    .child(badge::mode_badge(&mode, cx)),
            )
            .child(
                h_flex()
                    .gap(px(4.))
                    .flex_shrink_0()
                    .child(muted_icon_button(
                        ElementId::Name(format!("rule-edit-{index}").into()),
                        "pencil-outline",
                        26.,
                        16.,
                        cx,
                        move |_, window, cx| {
                            let _ = weak_edit.update(cx, move |page, cx| {
                                page.open_editor(Some(index), window, cx);
                            });
                        },
                    ))
                    .child(danger_icon_button(
                        ElementId::Name(format!("rule-delete-{index}").into()),
                        "delete-outline",
                        26.,
                        16.,
                        cx,
                        move |_, window, cx| {
                            let _ = weak_delete.update(cx, move |page, cx| {
                                page.delete_rule(index, window, cx);
                            });
                        },
                    )),
            )
            .into_any_element()
    }
}

impl Render for RulesPage {
    fn render(&mut self, _: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let host_rules: Vec<(usize, RuleConfig)> = self
            .rules
            .iter()
            .cloned()
            .enumerate()
            .filter(|(_, rule)| rule.rule_type.eq_ignore_ascii_case("HOST"))
            .collect();

        let geo_rules: Vec<(usize, RuleConfig)> = self
            .rules
            .iter()
            .cloned()
            .enumerate()
            .filter(|(_, rule)| rule.rule_type.eq_ignore_ascii_case("GEO"))
            .collect();

        v_flex()
            .size_full()
            .child(
                h_flex()
                    .items_center()
                    .justify_between()
                    .mb_4()
                    .pr_6()
                    .child(
                        h_flex()
                            .items_center()
                            .gap_2()
                            .child(
                                div()
                                    .text_size(px(20.))
                                    .font_weight(FontWeight::SEMIBOLD)
                                    .child(i18n::t("RULES")),
                            )
                            .child(badge::title_count(self.rules.len(), cx)),
                    )
                    .child(
                        Button::new("add-rule")
                            .primary()
                            .small()
                            .label(i18n::t("ADD_RULE"))
                            .icon(Icon::default().path(mdi("add")))
                            .on_click(cx.listener(|this, _, window, cx| {
                                this.open_editor(None, window, cx)
                            })),
                    ),
            )
            .child(
                v_flex()
                    .id("rules-scroll")
                    .flex_1()
                    .min_h_0()
                    .gap_2()
                    .pr_6()
                    .overflow_y_scrollbar()
                    .child(self.section(
                        i18n::t("HOST"),
                        self.host_open,
                        host_rules,
                        true,
                        cx,
                    ))
                    .child(self.section(
                        i18n::t("GEO"),
                        self.geo_open,
                        geo_rules,
                        false,
                        cx,
                    )),
            )
    }
}
