use crate::core::types::{CountryCodeItem, RuleConfig};
use crate::core::Core;
use crate::ui::i18n;
use gpui_kit::base::{h_flex, v_flex};
use gpui_kit::component::WindowExt as _;
use gpui_kit::component::button::{Button, ButtonVariants as _};
use gpui_kit::component::input::{Input, InputState};
use gpui_kit::component::select::{SearchableVec, Select, SelectState};
use gpui_kit::component::{ActiveTheme as _, IndexPath};
use gpui_kit::*;
use std::sync::Arc;

type StrSelect = Entity<SelectState<SearchableVec<SharedString>>>;

#[derive(Clone)]
pub struct RulePrefill {
    pub rule_type: String,
    pub match_str: String,
    pub mode: String,
}

impl RulePrefill {
    pub fn new(rule_type: &str, match_str: String, mode: &str) -> Self {
        Self {
            rule_type: rule_type.to_string(),
            match_str,
            mode: mode.to_string(),
        }
    }

    pub fn from_rule(rule: &RuleConfig) -> Self {
        Self {
            rule_type: rule.rule_type.clone(),
            match_str: rule.match_str.clone(),
            mode: rule.mode.clone(),
        }
    }
}

pub fn open_rule_dialog(
    core: Arc<Core>,
    prefill: RulePrefill,
    editing: Option<usize>,
    on_done: Arc<dyn Fn(&mut App)>,
    window: &mut Window,
    cx: &mut App,
) {
    let type_index = if prefill.rule_type.eq_ignore_ascii_case("GEO") {
        1
    } else {
        0
    };
    let mode_index = if prefill.mode.eq_ignore_ascii_case("PROXY") {
        1
    } else {
        0
    };

    let type_state: StrSelect = cx.new(|cx| {
        SelectState::new(
            SearchableVec::new(vec!["HOST".into(), "GEO".into()]),
            Some(IndexPath::new(type_index)),
            window,
            cx,
        )
    });

    let mode_state: StrSelect = cx.new(|cx| {
        SelectState::new(
            SearchableVec::new(vec!["DIRECT".into(), "PROXY".into()]),
            Some(IndexPath::new(mode_index)),
            window,
            cx,
        )
    });

    let match_input = cx.new(|cx| {
        InputState::new(window, cx)
            .default_value(prefill.match_str.clone())
            .placeholder("*.example.com")
    });

    let countries = Arc::new(core.geo_countries());
    let country_labels: Vec<SharedString> = countries
        .iter()
        .map(|country| country_label(country).into())
        .collect();
    let country_index = countries
        .iter()
        .position(|country| country.alpha2_code.eq_ignore_ascii_case(&prefill.match_str));

    let country_state: StrSelect = cx.new(|cx| {
        SelectState::new(
            SearchableVec::new(country_labels),
            country_index.map(IndexPath::new),
            window,
            cx,
        )
    });

    let title = if editing.is_some() {
        i18n::t("EDIT_RULE")
    } else {
        i18n::t("ADD_RULE")
    };

    window.open_dialog(cx, move |dialog, _, cx| {
        let rule_type = selected_value(&type_state, cx);
        let is_geo = rule_type == "GEO";

        let match_control: AnyElement = if is_geo {
            div()
                .w_full()
                .child(
                    Select::new(&country_state)
                        .placeholder(i18n::t("SELECT_COUNTRY")),
                )
                .into_any_element()
        } else {
            div()
                .w_full()
                .child(Input::new(&match_input))
                .into_any_element()
        };

        let body = v_flex()
            .gap_3()
            .child(field(
                i18n::t("TYPE"),
                cx,
                div()
                    .w_full()
                    .child(
                        Select::new(&type_state)
                            .placeholder(i18n::t("SELECT_RULE_TYPE")),
                    )
                    .into_any_element(),
            ))
            .child(field(i18n::t("MATCH"), cx, match_control))
            .child(field(
                i18n::t("MODE"),
                cx,
                div()
                    .w_full()
                    .child(
                        Select::new(&mode_state)
                            .placeholder(i18n::t("SELECT_MODE")),
                    )
                    .into_any_element(),
            ));

        let type_for_save = type_state.clone();
        let mode_for_save = mode_state.clone();
        let country_for_save = country_state.clone();
        let input_for_save = match_input.clone();
        let countries_for_save = countries.clone();
        let core_for_save = core.clone();
        let on_done_for_save = on_done.clone();

        let footer = {
            let footer_type = type_for_save.clone();
            let footer_mode = mode_for_save.clone();
            let footer_country = country_for_save.clone();
            let footer_input = input_for_save.clone();
            let footer_countries = countries_for_save.clone();
            let footer_core = core_for_save.clone();
            let footer_on_done = on_done_for_save.clone();

            h_flex()
                .justify_end()
                .gap_2()
                .child(
                    Button::new("rule-cancel")
                        .label(i18n::t("CLOSE"))
                        .on_click(|_, window, cx| window.close_dialog(cx)),
                )
                .child(
                    Button::new("rule-save")
                        .primary()
                        .label(if editing.is_some() {
                            i18n::t("SAVE")
                        } else {
                            i18n::t("ADD_RULE")
                        })
                        .on_click(move |_, window, cx| {
                            let rule_type = selected_value(&footer_type, cx);
                            let mode = selected_value(&footer_mode, cx);

                            let match_str = if rule_type == "GEO" {
                                footer_country
                                    .read(cx)
                                    .selected_value()
                                    .and_then(|label| {
                                        footer_countries
                                            .iter()
                                            .find(|country| {
                                                country_label(country).as_str() == label.as_ref()
                                            })
                                            .map(|country| country.alpha2_code.clone())
                                    })
                                    .unwrap_or_default()
                            } else {
                                footer_input.read(cx).value().to_string()
                            };

                            let match_str = match_str.trim().to_string();
                            if match_str.is_empty() {
                                return;
                            }

                            let rule = RuleConfig {
                                rule_type: if rule_type.is_empty() {
                                    "HOST".to_string()
                                } else {
                                    rule_type
                                },
                                match_str,
                                mode: if mode.is_empty() {
                                    "DIRECT".to_string()
                                } else {
                                    mode
                                },
                            };

                            let duplicate = footer_core
                                .snapshot_rules()
                                .unwrap_or_default()
                                .iter()
                                .enumerate()
                                .any(|(index, existing)| {
                                    Some(index) != editing
                                        && existing
                                            .rule_type
                                            .eq_ignore_ascii_case(&rule.rule_type)
                                        && existing
                                            .match_str
                                            .eq_ignore_ascii_case(&rule.match_str)
                                });
                            if duplicate {
                                window.push_notification(
                                    format!(
                                        "{}: {}",
                                        i18n::t("DUPLICATE_RULE_TITLE"),
                                        i18n::t("DUPLICATE_RULE")
                                    ),
                                    cx,
                                );
                                return;
                            }

                            let handle = match editing {
                                Some(id) => footer_core.save_rule(id, rule),
                                None => footer_core.add_rule(rule),
                            };

                            let on_done = footer_on_done.clone();
                            cx.spawn(async move |cx| {
                                let _ = handle.await;
                                cx.update(|cx| on_done(cx));
                            })
                            .detach();

                            window.close_dialog(cx);
                        }),
                )
        };

        dialog
            .w(px(380.))
            .title(title.clone())
            .child(body)
            .footer(footer)
    });
}

fn selected_value(state: &StrSelect, cx: &App) -> String {
    state
        .read(cx)
        .selected_value()
        .map(|value| value.to_string())
        .unwrap_or_default()
}

fn country_label(country: &CountryCodeItem) -> String {
    format!("{} ({})", country.country, country.alpha2_code)
}

fn field(label: String, cx: &App, control: AnyElement) -> AnyElement {
    v_flex()
        .gap_1()
        .child(
            div()
                .text_sm()
                .text_color(cx.theme().muted_foreground)
                .child(format!("{label}:")),
        )
        .child(control)
        .into_any_element()
}
